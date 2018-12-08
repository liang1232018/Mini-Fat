/*
 *   _|                                      _|_|_|_|            _|
 *   _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
 *   _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
 *   _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
 *   _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

#include <assert.h>
#include <stdio.h>

#include <iostream>
#include <map>
#include <vector>
#include <set>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/TypeBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

extern "C"
{
#include "lowfat_config.inc"
#include "lowfat.h"
}

using namespace llvm;
using namespace std;

/*
 * Type decls.
 */
typedef vector<tuple<Instruction *, Value *, unsigned>> Plan;
typedef map<Value *, Value *> PtrInfo;

/*
 * A bounds object represents a range lb..ub.  As a simplification, the lower
 * bounds is always fixed to (0) since 99% of the time this is sufficient.
 */
struct Bounds
{
    static const int64_t NONFAT_BOUND  = INT64_MAX;
    static const int64_t UNKNOWN_BOUND = INT64_MIN;

    static const int64_t lb = 0;
    int64_t ub;

    Bounds() : ub(0)
    {

    }

    Bounds(size_t lb, size_t ub) : ub(ub)
    {
        if (lb != 0)
            ub = UNKNOWN_BOUND;
    }

    static Bounds empty()
    {
        return Bounds();
    }

    static Bounds nonFat()
    {
        return Bounds(0, NONFAT_BOUND);
    }

    static Bounds unknown()
    {
        return Bounds(0, UNKNOWN_BOUND);
    }

    bool isUnknown()
    {
        return (ub == UNKNOWN_BOUND);
    }

    bool isNonFat()
    {
        return (ub == NONFAT_BOUND);
    }

    bool isInBounds(int64_t k = 0)
    {
        return (k >= lb && k <= ub);
    }

    Bounds &operator-=(size_t k)
    {
        if (k == 0)
            return *this;
        if (isUnknown() || isNonFat())
            return *this;
        if (k > (size_t)ub)
            ub = UNKNOWN_BOUND;
        else
            ub -= (int64_t)k;
        return *this;
    }

    static Bounds min(Bounds bounds1, Bounds bounds2)
    {
        return Bounds(0, std::min(bounds1.ub, bounds2.ub));
    }
};

typedef map<Value *, Bounds> BoundsInfo;

/*
 * Prototypes.
 */
static Bounds getPtrBounds(const TargetLibraryInfo *TLI, const DataLayout *DL,
    Value *Ptr, BoundsInfo &boundsInfo);
static Value *calcBasePtr(Function *F, Value *Ptr);
static Value *calcBasePtr(const TargetLibraryInfo *TLI, Function *F,
    Value *Ptr, PtrInfo &baseInfo);
static void getInterestingInsts(const TargetLibraryInfo *TL,
    const DataLayout *DL, BoundsInfo &boundsInfo, Instruction *I, Plan &plan);
static void insertBoundsCheck(const DataLayout *DL, Instruction *I, Value *Ptr,
    unsigned info, const PtrInfo &baseInfo);
static bool isInterestingAlloca(Instruction *I);
static bool isInterestingGlobal(GlobalVariable *GV);

/*
 * Options
 */
static cl::opt<bool> option_debug("lowfat-debug",
    cl::desc("Dump before-and-after LowFat instrumented LLVM IR"));
static cl::opt<bool> option_no_check_reads("lowfat-no-check-reads",
    cl::desc("Do not OOB-check reads"));
static cl::opt<bool> option_no_check_writes("lowfat-no-check-writes",
    cl::desc("Do not OOB-check writes"));
static cl::opt<bool> option_no_check_escapes("lowfat-no-check-escapes",
    cl::desc("Do not OOB-check pointer escapes"));
static cl::opt<bool> option_no_check_memset("lowfat-no-check-memset",
    cl::desc("Do not OOB-check memset"));
static cl::opt<bool> option_no_check_memcpy("lowfat-no-check-memcpy",
    cl::desc("Do not OOB-check memcpy or memmove"));
static cl::opt<bool> option_no_check_escape_call("lowfat-no-check-escape-call",
    cl::desc("Do not OOB-check pointer call escapes"));
static cl::opt<bool> option_no_check_escape_return(
    "lowfat-no-check-escape-return",
    cl::desc("Do not OOB-check pointer return escapes"));
static cl::opt<bool> option_no_check_escape_store(
    "lowfat-no-check-escape-store",
    cl::desc("Do not OOB-check pointer store escapes"));
static cl::opt<bool> option_no_check_escape_ptr2int(
    "lowfat-no-check-escape-ptr2int",
    cl::desc("Do not OOB-check pointer pointer-to-int escapes"));
static cl::opt<bool> option_no_check_escape_insert(
    "lowfat-no-check-escape-insert",
    cl::desc("Do not OOB-check pointer vector insert escapes"));
static cl::opt<bool> option_no_check_fields(
    "lowfat-no-check-fields",
    cl::desc("Do not OOB-check field access (reduces the number of checks)"));
static cl::opt<bool> option_check_whole_access(
    "lowfat-check-whole-access",
    cl::desc("OOB-check the whole pointer access ptr..ptr+sizeof(*ptr) as "
        "opposed to just ptr (increases the number and cost of checks)"));
static cl::opt<bool> option_no_replace_malloc(
    "lowfat-no-replace-malloc",
    cl::desc("Do not replace malloc() with LowFat malloc() "
        "(disables heap protection)"));
static cl::opt<bool> option_no_replace_alloca(
    "lowfat-no-replace-alloca",
    cl::desc("Do not replace stack allocation (alloca) with LowFat stack "
        "allocation (disables stack protection)"));
static cl::opt<bool> option_no_replace_globals(
    "lowfat-no-replace-globals",
    cl::desc("Do not replace globals with LowFat globals "
        "(disables global variable protection; should also be combined with "
        "-mcmodel=small)"));
static cl::opt<string> option_no_check_blacklist(
    "lowfat-no-check-blacklist",
    cl::desc("Do not OOB-check the functions/modules specified in the "
        "given blacklist"),
    cl::init("-"));
static cl::opt<bool> option_no_abort(
    "lowfat-no-abort",
    cl::desc("Do not abort the program if an OOB memory error occurs"));

/*
 * Fool-proof "leading zero count" implementation.  Also works for "0".
 */
static size_t clzll(uint64_t x)
{
    if (x == 0)
        return 64;
    uint64_t bit = (uint64_t)1 << 63;
    size_t count = 0;
    while ((x & bit) == 0)
    {
        count++;
        bit >>= 1;
    }
    return count;
}

/*
 * Test if we should ignore instrumentation for this pointer.
 */
static bool filterPtr(unsigned kind)
{
    switch (kind)
    {
        case LOWFAT_OOB_ERROR_READ:
            return option_no_check_reads;
        case LOWFAT_OOB_ERROR_WRITE:
            return option_no_check_writes;
        case LOWFAT_OOB_ERROR_MEMSET:
            return option_no_check_memset;
        case LOWFAT_OOB_ERROR_MEMCPY_ONE:
        case LOWFAT_OOB_ERROR_MEMCPY_TWO:
        case LOWFAT_OOB_ERROR_MEMCPY:
            return option_no_check_memcpy;
        case LOWFAT_OOB_ERROR_ESCAPE_CALL:
            return option_no_check_escape_call || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_RETURN:
            return option_no_check_escape_return || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_STORE:
            return option_no_check_escape_store || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_PTR2INT:
            return option_no_check_escape_ptr2int || option_no_check_escapes;
        case LOWFAT_OOB_ERROR_ESCAPE_INSERT:
            return option_no_check_escape_insert || option_no_check_escapes;
        default:
            return false;
    }
}

/*
 * LowFat warning message class.
 */
class LowFatWarning : public DiagnosticInfo
{
    private:
        string msg;
    
    public:
        LowFatWarning(const char *msg) : DiagnosticInfo(777, DS_Warning),
            msg(msg) { }
        void print(DiagnosticPrinter &dp) const override;
};

void LowFatWarning::print(DiagnosticPrinter &dp) const
{
    dp << "[LowFat] Warning: " << msg << "\n";
}

/*
 * Find the best place to insert instructions *after* `Ptr' is defined.
 */
static pair<BasicBlock *, BasicBlock::iterator> nextInsertPoint(Function *F,
    Value *Ptr)
{
    if (InvokeInst *Invoke = dyn_cast<InvokeInst>(Ptr))
    {
        // This is a tricky case since we an invoke instruction is also a
        // terminator.  Instead we create a new BasicBlock to insert into.
        BasicBlock *fromBB = Invoke->getParent();
        BasicBlock *toBB = Invoke->getNormalDest();
        BasicBlock *newBB = SplitEdge(fromBB, toBB);
        return make_pair(newBB, newBB->begin());
    }
    else if (isa<Argument>(Ptr) || isa<GlobalValue>(Ptr))
    {
        // For arguments or globals we insert into the entry basic block.
        BasicBlock &Entry = F->getEntryBlock();
        return make_pair(&Entry, Entry.begin());
    }
    else if (isa<Instruction>(Ptr) && !isa<TerminatorInst>(Ptr))
    {
        Instruction *I = dyn_cast<Instruction>(Ptr);
        assert(I != nullptr);
        BasicBlock::iterator i(I);
        i++;
        BasicBlock *BB = I->getParent();
        return make_pair(BB, i);
    }
    else
    {
        Ptr->getContext().diagnose(LowFatWarning(
            "(BUG) failed to calculate insert point"));
        BasicBlock &Entry = F->getEntryBlock();
        return make_pair(&Entry, Entry.begin());
    }
}

/*
 * Replace:
 *     ptr = lowfat_malloc(size);
 * with
 *     ptr = lowfat_malloc_index(idx, size);
 * If `size' is a constant and therefore `idx' can be calculated statically.
 * This saves a few CPU cycles per malloc call.
 */
static void optimizeMalloc(Module *M, Instruction *I,
    vector<Instruction *> &dels)
{
    CallSite Call(I);
    if (!Call.isCall() && !Call.isInvoke())
        return;
    Function *F = Call.getCalledFunction();
    if (F == nullptr || !F->hasName())
        return;
    if (Call.getNumArgOperands() != 1)
        return;
    switch (Call.getNumArgOperands())
    {
        case 1:
            if (F->getName() != "lowfat_malloc" &&
                    F->getName() != "lowfat__Znwm" &&
                    F->getName() != "lowfat__Znam")
                return;
            break;
        case 2:
            if (F->getName() != "lowfat__ZnwmRKSt9nothrow_t" &&
                    F->getName() != "lowfat__ZnamRKSt9nothrow_t")
                return;
            break;
        default:
            return;
    }
    // Value *Arg = Call.getArgOperand(0);
    // ConstantInt *Size = dyn_cast<ConstantInt>(Arg);
    // if (Size == nullptr)
    // {
    //     // Malloc argument is not a constant; skip.
    //     return;
    // }
    // size_t size = Size->getValue().getZExtValue();
    // size_t idx = lowfat_heap_select(size);

    // IRBuilder<> builder(I);
    // Constant *MallocIdx = M->getOrInsertFunction("lowfat_malloc_index",
    //     builder.getInt8PtrTy(), builder.getInt64Ty(), builder.getInt64Ty(),
    //     nullptr);
    // ConstantInt *Idx = builder.getInt64(idx);

    // 只优化定值的size 我们优化所有，将lowfat_malloc 替换成 minifat_malloc
    Value *Arg = Call.getArgOperand(0);
    
    IRBuilder<> builder(I);
    Constant *Minifat_Malloc = M->getOrInsertFunction("minifat_malloc",
        builder.getInt8PtrTy(), builder.getInt64Ty(), nullptr);

    Value *NewCall = nullptr;
    Value *Size = builder.CreateBitCast(Arg, builder.getInt64Ty());
    if (auto *Invoke = dyn_cast<InvokeInst>(I))
    {
        InvokeInst *NewInvoke = builder.CreateInvoke(Minifat_Malloc,
            Invoke->getNormalDest(), Invoke->getUnwindDest(), {Size});
        NewInvoke->setDoesNotThrow();
        NewCall = NewInvoke;
    }
    else
        NewCall = builder.CreateCall(Minifat_Malloc, {Size});
    I->replaceAllUsesWith(NewCall);
    dels.push_back(I);
}

/*
 * Test if the given pointer is a memory allocation.  If so, then we know
 * that is pointer is already a base-pointer, so no need to call
 * lowfat_base().
 * TODO: I had planed to use TLI for this, but appears not to work correctly.
 */
static bool isMemoryAllocation(const TargetLibraryInfo *TLI, Value *Ptr)
{
    if (option_no_replace_malloc)
        return false;
    Function *F = nullptr;
    if (CallInst *Call = dyn_cast<CallInst>(Ptr))
        F = Call->getCalledFunction();
    else if (InvokeInst *Invoke = dyn_cast<InvokeInst>(Ptr))
        F = Invoke->getCalledFunction();
    else
        return false;
    if (F == nullptr)
        return false;
    if (!F->hasName())
        return false;
    const string &Name = F->getName().str();
    if (Name == "malloc" || Name == "realloc" || Name == "_Znwm" ||
            Name == "_Znam" || Name == "_ZnwmRKSt9nothrow_t" ||
            Name == "_ZnamRKSt9nothrow_t" || Name == "calloc" ||
            Name == "valloc" || Name == "strdup" || Name == "strndup")
        return true;
    return false;
}

/*
 * Get the (assumed) bounds of input pointers.  By default this is the "empty"
 * bounds, meaning that the pointer is assumed to be within bounds, but any
 * pointer arithmetic is assumed to be possibly-OOB.
 *
 * If `option_no_check_fields` is set, then offsets [0..sizeof(*ptr)] will be
 * assumed to be within bounds, effectively meaning that fields are never
 * bounds checked.  (This emulates the behavior of some other bounds checkers
 * like BaggyBounds and PAriCheck).
 */
static Bounds getInputPtrBounds(const DataLayout *DL, Value *Ptr)
{
    if (!option_no_check_fields)
        return Bounds::empty();
    Type *Ty = Ptr->getType();
    PointerType *PtrTy = dyn_cast<PointerType>(Ty);
    if (PtrTy == nullptr)
        return Bounds::empty();
    Ty = PtrTy->getElementType();
    if (!Ty->isSized())
        return Bounds::empty();
    size_t size = DL->getTypeAllocSize(Ty);
    return Bounds(0, size);
}

/*
 * Get the size of a constant object.  This is very similar to getPtrBounds()
 * defined below.
 */
static Bounds getConstantPtrBounds(const TargetLibraryInfo *TLI,
    const DataLayout *DL, Constant *C, BoundsInfo &boundsInfo)
{
    if (isa<ConstantPointerNull>(C))
        return Bounds::nonFat();
    else if (isa<UndefValue>(C))
        return Bounds::nonFat();

    auto i = boundsInfo.find(C);
    if (i != boundsInfo.end())
        return i->second;

    Bounds bounds = Bounds::nonFat();
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(C))
    {
        Type *Ty = GV->getType();
        PointerType *PtrTy = dyn_cast<PointerType>(Ty);
        assert(PtrTy != nullptr);
        Ty = PtrTy->getElementType();
        size_t size = DL->getTypeAllocSize(Ty);
        if (size != 0)
        {
            // (size==0) implies unspecified size, e.g. int x[];
            bounds = Bounds(0, size);
        }
    }
    else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C))
    {
        switch (CE->getOpcode())
        {
            case Instruction::GetElementPtr:
            {
                GEPOperator *GEP = cast<GEPOperator>(CE);
                assert(GEP != nullptr);
                bounds = getPtrBounds(TLI, DL, GEP->getPointerOperand(),
                    boundsInfo);
                if (!bounds.isUnknown() && !bounds.isNonFat())
                {
                    APInt offset(64, 0);
                    if (GEP->accumulateConstantOffset(*DL, offset) &&
                            offset.isNonNegative())
                        bounds -= offset.getZExtValue();
                    else
                        bounds = Bounds::unknown();
                }
                break;
            }
            case Instruction::BitCast:
                bounds = getConstantPtrBounds(TLI, DL, CE->getOperand(0),
                    boundsInfo);
                break;
            case Instruction::Select:
            {
                Bounds bounds1 = getConstantPtrBounds(TLI, DL,
                    CE->getOperand(1), boundsInfo);
                Bounds bounds2 = getConstantPtrBounds(TLI, DL,
                    CE->getOperand(2), boundsInfo);
                bounds = Bounds::min(bounds1, bounds2);
                break;
            }
            case Instruction::IntToPtr:
            case Instruction::ExtractElement:
            case Instruction::ExtractValue:
                // Assumed to be non-fat pointers:
                bounds = Bounds::nonFat();
                break;
            default:
            {
                C->dump();
                C->getContext().diagnose(LowFatWarning(
                    "(BUG) unknown constant expression pointer type (size)"));
                break;
            }
        }
    }
    else if (isa<GlobalValue>(C))
        bounds = Bounds::nonFat();
    else
    {
        C->dump();
        C->getContext().diagnose(LowFatWarning(
            "(BUG) unknown constant pointer type (size)"));
    }

    boundsInfo.insert(make_pair(C, bounds));
    return bounds;
}

/*
 * Analysis that attempts to statically determine the (approx.) bounds of the
 * given object pointed to by `Ptr'.
 */
static Bounds getPtrBounds(const TargetLibraryInfo *TLI, const DataLayout *DL,
    Value *Ptr, BoundsInfo &boundsInfo)
{
    auto i = boundsInfo.find(Ptr);
    if (i != boundsInfo.end())
        return i->second;

    Bounds bounds = Bounds::nonFat();
    if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Ptr))
    {
        bounds = getPtrBounds(TLI, DL, GEP->getPointerOperand(), boundsInfo);
        if (!bounds.isUnknown() && !bounds.isNonFat())
        {
            APInt offset(64, 0);
            if (GEP->accumulateConstantOffset(*DL, offset) &&
                    offset.isNonNegative())
                bounds -= offset.getZExtValue();
            else
                bounds = Bounds::unknown();
        }
    }
    else if (AllocaInst *Alloca = dyn_cast<AllocaInst>(Ptr))
    {
        const Value *Size = Alloca->getArraySize();
        if (isa<ConstantInt>(Size) && Alloca->getAllocatedType()->isSized())
            bounds = Bounds(0, dyn_cast<ConstantInt>(Size)->getZExtValue() *
                DL->getTypeAllocSize(Alloca->getAllocatedType()));
        else
            bounds = getInputPtrBounds(DL, Ptr);
    }
    else if (BitCastInst *Cast = dyn_cast<BitCastInst>(Ptr))
        bounds = getPtrBounds(TLI, DL, Cast->getOperand(0), boundsInfo);
    else if (SelectInst *Select = dyn_cast<SelectInst>(Ptr))
    {
        Bounds bounds1 = getPtrBounds(TLI, DL, Select->getOperand(1),
            boundsInfo);
        Bounds bounds2 = getPtrBounds(TLI, DL, Select->getOperand(2),
            boundsInfo);
        bounds = Bounds::min(bounds1, bounds2);
    }
    else if (Constant *C = dyn_cast<Constant>(Ptr))
        bounds = getConstantPtrBounds(TLI, DL, C, boundsInfo);
    else if (isa<ConstantPointerNull>(Ptr) ||
             isa<GlobalValue>(Ptr) ||
             isa<UndefValue>(Ptr))                  // Treat as non-fat
        bounds = Bounds::nonFat();
    else if (isa<IntToPtrInst>(Ptr) ||
                isa<Argument>(Ptr) ||
                isa<LoadInst>(Ptr) ||
                isa<ExtractValueInst>(Ptr) ||
                isa<ExtractElementInst>(Ptr))
        bounds = getInputPtrBounds(DL, Ptr);        // Input pointers.
    else if (isa<CallInst>(Ptr) || isa<InvokeInst>(Ptr))
    {
        uint64_t size;
        if (isMemoryAllocation(TLI, Ptr) && getObjectSize(Ptr, size, *DL, TLI))
            bounds = Bounds(0, size);
        else
            bounds = getInputPtrBounds(DL, Ptr);    // Input pointer (default).
    }
    else if (PHINode *PHI = dyn_cast<PHINode>(Ptr))
    {
        size_t numValues = PHI->getNumIncomingValues();
        bounds = Bounds::nonFat();
        boundsInfo.insert(make_pair(Ptr, Bounds::unknown()));
        for (size_t i = 0; i < numValues; i++)
        {
            Bounds boundsIn = getPtrBounds(TLI, DL, PHI->getIncomingValue(i),
                boundsInfo);
            bounds = Bounds::min(bounds, boundsIn);
            if (bounds.isUnknown())
                break;      // No point continuing.
        }
        boundsInfo.erase(Ptr);
    }
    else
    {
        Ptr->dump();
        Ptr->getContext().diagnose(LowFatWarning(
                    "(BUG) unknown pointer type (size)"));
    }

    boundsInfo.insert(make_pair(Ptr, bounds));
    return bounds;
}

/*
 * Insert an explicit lowfat_base(Ptr) operation after Ptr's origin.
 */
static Value *calcBasePtr(Function *F, Value *Ptr)
{
    auto i = nextInsertPoint(F, Ptr);
    IRBuilder<> builder(i.first, i.second);
    Module *M = F->getParent();
    Value *G = M->getOrInsertFunction("lowfat_base",
        builder.getInt8PtrTy(), builder.getInt8PtrTy(), nullptr);
    Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
    Value *BasePtr = builder.CreateCall(G, {Ptr});
    return BasePtr;
}

/*
 * Calculate the base pointer of a constant.
 */
static Constant *calcBasePtr(const TargetLibraryInfo *TLI, Function *F,
    Constant *C, PtrInfo &baseInfo)
{
    if (option_no_replace_globals)
        return ConstantPointerNull::get(Type::getInt8PtrTy(C->getContext()));

    ConstantExpr *CE = dyn_cast<ConstantExpr>(C);
    if (CE == nullptr)
        return ConstantExpr::getPointerCast(C,
            Type::getInt8PtrTy(C->getContext()));

    auto i = baseInfo.find(C);
    if (i != baseInfo.end())
    {
        Constant *R = dyn_cast<Constant>(i->second);
        assert(R != nullptr);
        return R;
    }

    Constant *BasePtr = nullptr;
    switch (CE->getOpcode())
    {
        case Instruction::GetElementPtr:
        {
            GEPOperator *GEP = cast<GEPOperator>(CE);
            assert(GEP != nullptr);
            Value *Ptr = GEP->getPointerOperand();
            Constant *CPtr = dyn_cast<Constant>(Ptr);
            assert(CPtr != nullptr);
            BasePtr = calcBasePtr(TLI, F, CPtr, baseInfo);
            break;
        }
        case Instruction::BitCast:
            BasePtr = calcBasePtr(TLI, F, CE->getOperand(0), baseInfo);
            break;
        case Instruction::Select:
        {
            Constant *BasePtrA = calcBasePtr(TLI, F, CE->getOperand(1),
                baseInfo);
            Constant *BasePtrB = calcBasePtr(TLI, F, CE->getOperand(2),
                baseInfo);
            BasePtr = ConstantExpr::getSelect(CE->getOperand(0), BasePtrA,
                BasePtrB);
            break;
        }
        case Instruction::IntToPtr:
        case Instruction::ExtractElement:
        case Instruction::ExtractValue:
            // Assumed to be non-fat pointers:
            BasePtr = 
                ConstantPointerNull::get(Type::getInt8PtrTy(CE->getContext()));
            break;
        default:
        {
            C->dump();
            C->getContext().diagnose(LowFatWarning(
                "(BUG) unknown constant expression pointer type (base)"));
            BasePtr = 
                ConstantPointerNull::get(Type::getInt8PtrTy(CE->getContext()));
            break;
        }
    }

    baseInfo.insert(make_pair(C, BasePtr));
    return BasePtr;
}

/*
 * Calculates the base pointer of an object.  The base pointer of `ptr' is:
 * - NULL if ptr==NULL or other non-fat pointer.
 * - ptr if ptr is the result of an allocation (e.g. malloc() or alloca())
 * - lowfat_base(ptr) otherwise.
 * See Figure 2 from "Heap Bounds Protection with Low Fat Pointers", except:
 * - Size is no longer propagated explicitly (instead we re-calculate from the
 *   base); and
 * - We also handle stack and global objects.
 */
static Value *calcBasePtr(const TargetLibraryInfo *TLI, Function *F,
    Value *Ptr, PtrInfo &baseInfo)
{
    auto i = baseInfo.find(Ptr);
    if (i != baseInfo.end())
        return i->second;

    Value *BasePtr = ConstantPointerNull::get(
        Type::getInt8PtrTy(Ptr->getContext()));
    if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Ptr))
        BasePtr = calcBasePtr(TLI, F, GEP->getPointerOperand(), baseInfo);
    else if (AllocaInst *Alloca = dyn_cast<AllocaInst>(Ptr))
    {
        if (isInterestingAlloca(Alloca))
        {
            auto i = nextInsertPoint(F, Ptr);
            IRBuilder<> builder(i.first, i.second);
            BasePtr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
        }
    }
    else if (BitCastInst *Cast = dyn_cast<BitCastInst>(Ptr))
        BasePtr = calcBasePtr(TLI, F, Cast->getOperand(0), baseInfo);
    else if (SelectInst *Select = dyn_cast<SelectInst>(Ptr))
    {
        Value *BasePtrA = calcBasePtr(TLI, F, Select->getOperand(1),
            baseInfo);
        Value *BasePtrB = calcBasePtr(TLI, F, Select->getOperand(2),
            baseInfo);
        IRBuilder<> builder(Select);
        BasePtr = builder.CreateSelect(Select->getOperand(0), BasePtrA,
            BasePtrB);
    }
    else if (Constant *C = dyn_cast<Constant>(Ptr))
        BasePtr = calcBasePtr(TLI, F, C, baseInfo);
    else if (isa<IntToPtrInst>(Ptr) ||
                isa<Argument>(Ptr) ||
                isa<LoadInst>(Ptr) ||
                isa<ExtractValueInst>(Ptr) ||
                isa<ExtractElementInst>(Ptr))
        BasePtr = calcBasePtr(F, Ptr);
    else if (isa<CallInst>(Ptr) || isa<InvokeInst>(Ptr))
    {
        if (isMemoryAllocation(TLI, Ptr))
        {
            auto i = nextInsertPoint(F, Ptr);
            IRBuilder<> builder(i.first, i.second);
            BasePtr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
        }
        else
            BasePtr = calcBasePtr(F, Ptr);
    }
    else if (PHINode *PHI = dyn_cast<PHINode>(Ptr))
    {
        size_t numValues = PHI->getNumIncomingValues();
        IRBuilder<> builder(PHI);
        PHINode *BasePHI = builder.CreatePHI(builder.getInt8PtrTy(),
            numValues);
        baseInfo.insert(make_pair(Ptr, BasePHI));
        for (size_t i = 0; i < numValues; i++)
            BasePHI->addIncoming(UndefValue::get(builder.getInt8PtrTy()),
                PHI->getIncomingBlock(i));
        bool allNonFat = true;
        for (size_t i = 0; i < numValues; i++)
        {
            Value *BasePtr = calcBasePtr(TLI, F, PHI->getIncomingValue(i),
                baseInfo);
            if (!isa<ConstantPointerNull>(BasePtr))
                allNonFat = false;
            BasePHI->setIncomingValue(i, BasePtr);
        }
        if (allNonFat)
        {
            // Cannot erase the PHI since it may exist in baseInfo.
            baseInfo.erase(Ptr);
            baseInfo.insert(make_pair(Ptr, BasePtr));
            return BasePtr;
        }
        return BasePHI;
    }
    else
    {
        Ptr->dump();
        Ptr->getContext().diagnose(LowFatWarning(
                    "(BUG) unknown pointer type (base)"));
        BasePtr =
            ConstantPointerNull::get(Type::getInt8PtrTy(Ptr->getContext()));
    }

    baseInfo.insert(make_pair(Ptr, BasePtr));
    return BasePtr;
}

/*
 * Test if an integer value escapes or not.  If it does not, then there is no
 * point bounds checking pointer->integer casts.
 */
static bool doesIntEscape(Value *Val, set<Value *> &seen)
{
    if (seen.find(Val) != seen.end())
        return false;
    seen.insert(Val);

    // Sanity check:
    if (Val->getType()->isVoidTy())
    {
        Val->dump();
        Val->getContext().diagnose(LowFatWarning(
            "(BUG) unknown integer escape"));
        return true;
    }

    for (User *User: Val->users())
    {
        if (isa<ReturnInst>(User) ||
                isa<CallInst>(User) ||
                isa<InvokeInst>(User) ||
                isa<StoreInst>(User) ||
                isa<IntToPtrInst>(User))
            return true;
        if (isa<CmpInst>(User) ||
                isa<BranchInst>(User) ||
                isa<SwitchInst>(User))
            continue;
        if (doesIntEscape(User, seen))
            return true;
    }

    return false;
}

/*
 * Test if a pointer is an "ugly GEP" or not.  Ugly GEPs can violate the
 * bounds assumptions and this leads to false OOB errors.  Note that this is
 * only a problem if the LowFat pass is inserted late in the optimization
 * pipeline.  TODO: find a better solution.
 */
static bool isUglyGEP(Value *Val)
{
    Instruction *I = dyn_cast<Instruction>(Val);
    if (I == nullptr)
        return false;
    if (I->getMetadata("uglygep") != NULL)
        return true;
    else
        return false;
}

/*
 * Accumulate (into `plan') all interesting instructions and the corresponding
 * pointer to check.  Here "interesting" means that the instruction should
 * be bounds checked.
 */
static void addToPlan(const TargetLibraryInfo *TLI, const DataLayout *DL,
    BoundsInfo &boundsInfo, Plan &plan, Instruction *I, Value *Ptr,
    unsigned kind)
{
    if (filterPtr(kind))
        return;
    Bounds bounds = getPtrBounds(TLI, DL, Ptr, boundsInfo);
    size_t size = 0;
    if (option_check_whole_access &&
            (kind == LOWFAT_OOB_ERROR_READ || kind == LOWFAT_OOB_ERROR_WRITE))
    {
        Type *Ty = Ptr->getType();
        if (auto *PtrTy = dyn_cast<PointerType>(Ty))
        {
            Ty = PtrTy->getElementType();
            size = DL->getTypeAllocSize(Ty);
        }
    }
    if (bounds.isInBounds(size) && kind != LOWFAT_OOB_ERROR_ESCAPE_STORE) {
        kind = MINIFAT_PTR_INVALID;
    }
        
    plan.push_back(make_tuple(I, Ptr, kind));
}
static void getInterestingInsts(const TargetLibraryInfo *TLI,
    const DataLayout *DL, BoundsInfo &boundsInfo, Instruction *I, Plan &plan)
{
    if (I->getMetadata("nosanitize") != nullptr)
        return;
    Value *Ptr = nullptr;
    unsigned kind = LOWFAT_OOB_ERROR_UNKNOWN;
    if (StoreInst *Store = dyn_cast<StoreInst>(I))
    {
        Value *Val = Store->getValueOperand();
        if (Val->getType()->isPointerTy())
            addToPlan(TLI, DL, boundsInfo, plan, I, Val,
                LOWFAT_OOB_ERROR_ESCAPE_STORE);
        Ptr = Store->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_WRITE;
    }
    else if (LoadInst *Load = dyn_cast<LoadInst>(I))
    {
        Ptr = Load->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_READ;
    }
    else if (MemTransferInst *MI = dyn_cast<MemTransferInst>(I))
    {
        if (filterPtr(LOWFAT_OOB_ERROR_MEMCPY))
            return;
        IRBuilder<> builder(MI);
        Value *Src = builder.CreateBitCast(MI->getOperand(1),
            builder.getInt8PtrTy());
        Value *SrcEnd = builder.CreateGEP(Src,
            builder.CreateIntCast(MI->getOperand(2), builder.getInt64Ty(),
                false));
        addToPlan(TLI, DL, boundsInfo, plan, I, SrcEnd,
            LOWFAT_OOB_ERROR_MEMCPY_TWO);
        Value *Dst = builder.CreateBitCast(MI->getOperand(0),
            builder.getInt8PtrTy());
        Value *DstEnd = builder.CreateGEP(Dst,
            builder.CreateIntCast(MI->getOperand(2), builder.getInt64Ty(),
                false));
        addToPlan(TLI, DL, boundsInfo, plan, I, DstEnd,
            LOWFAT_OOB_ERROR_MEMCPY_ONE);
        return;
    }
    else if (MemSetInst *MI = dyn_cast<MemSetInst>(I))
    {
        if (filterPtr(LOWFAT_OOB_ERROR_MEMSET))
            return;
        IRBuilder<> builder(MI);
        Value *Dst = builder.CreateBitCast(MI->getOperand(0),
            builder.getInt8PtrTy());
        Value *DstEnd = builder.CreateGEP(Dst,
            builder.CreateIntCast(MI->getOperand(2), builder.getInt64Ty(),
                false));
        addToPlan(TLI, DL, boundsInfo, plan, I, DstEnd,
            LOWFAT_OOB_ERROR_MEMSET);
        return;
    }
    else if (PtrToIntInst *Ptr2Int = dyn_cast<PtrToIntInst>(I))
    {
        set<Value *> seen;
        if (!doesIntEscape(Ptr2Int, seen))
            return;
        Ptr = Ptr2Int->getPointerOperand();
        if (isUglyGEP(Ptr))
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_PTR2INT;
    }
    else if (CallInst *Call = dyn_cast<CallInst>(I))
    {
        Function *F = Call->getCalledFunction();
        if (F != nullptr && F->doesNotAccessMemory())
            return;
        for (unsigned i = 0; i < Call->getNumArgOperands(); i++)
        {
            Value *Arg = Call->getArgOperand(i);
            if (Arg->getType()->isPointerTy())
                addToPlan(TLI, DL, boundsInfo, plan, I, Arg,
                    LOWFAT_OOB_ERROR_ESCAPE_CALL);
        }
        return;
    }
    else if (InvokeInst *Invoke = dyn_cast<InvokeInst>(I))
    {
        Function *F = Invoke->getCalledFunction();
        if (F != nullptr && F->doesNotAccessMemory())
            return;
        for (unsigned i = 0; i < Invoke->getNumArgOperands(); i++)
        {
            Value *Arg = Invoke->getArgOperand(i);
            if (Arg->getType()->isPointerTy())
                addToPlan(TLI, DL, boundsInfo, plan, I, Arg,
                    LOWFAT_OOB_ERROR_ESCAPE_CALL);
        }
        return;
    }
    else if (ReturnInst *Return = dyn_cast<ReturnInst>(I))
    {
        Ptr = Return->getReturnValue();
        if (Ptr == nullptr || !Ptr->getType()->isPointerTy())
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_RETURN;
    }
    else if (InsertValueInst *Insert = dyn_cast<InsertValueInst>(I))
    {
        Ptr = Insert->getInsertedValueOperand();
        printf("test value\n");
        if (!Ptr->getType()->isPointerTy())
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_INSERT;
    }
    else if (InsertElementInst *Insert = dyn_cast<InsertElementInst>(I))
    {
        Ptr = Insert->getOperand(1);
        if (!Ptr->getType()->isPointerTy())
            return;
        kind = LOWFAT_OOB_ERROR_ESCAPE_INSERT;
    }
    else if (AtomicRMWInst *Atomic = dyn_cast<AtomicRMWInst>(I))
    {
        Ptr = Atomic->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_WRITE;
    }
    else if (AtomicCmpXchgInst *Atomic = dyn_cast<AtomicCmpXchgInst>(I))
    {
        Ptr = Atomic->getPointerOperand();
        kind = LOWFAT_OOB_ERROR_WRITE;
    }
    else
        return;

    addToPlan(TLI, DL, boundsInfo, plan, I, Ptr, kind); 
}

/*
 * Insert a bounds check before instruction `I'.
 */
// static int check_nums = 0;
static void insertBoundsCheck(const DataLayout *DL, Instruction *I, Value *Ptr,
    unsigned info, const PtrInfo &baseInfo)
{
    IRBuilder<> builder(I);
    auto i = baseInfo.find(Ptr);
    if (i == baseInfo.end())
    {
        missing_baseptr_error:
        Ptr->dump();
        Ptr->getContext().diagnose(LowFatWarning(
            "(BUG) missing base pointer"));
        return;
    }
    Value *BasePtr = i->second;
    if (BasePtr == nullptr)
        goto missing_baseptr_error;
    if (isa<ConstantPointerNull>(BasePtr))
    {
        // This is a nonfat pointer.
        return;
    }
    Module *M = builder.GetInsertBlock()->getParent()->getParent();
    size_t size = 0;
    if (option_check_whole_access &&
            (info == LOWFAT_OOB_ERROR_READ || info == LOWFAT_OOB_ERROR_WRITE))
    {
        Type *Ty = Ptr->getType();
        if (auto *PtrTy = dyn_cast<PointerType>(Ty))
        {
            Ty = PtrTy->getElementType();
            size = DL->getTypeAllocSize(Ty)-1;
        }
    }
    
    Value *Size = builder.getInt64(size);
    Value *TPtr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());

    // 如果在一定在界内，那么直接加指针操作即可
    if(info != MINIFAT_PTR_INVALID) {
        // check_nums++;
        // printf("check_nums %d\n",check_nums);

        Value *BoundsCheck = M->getOrInsertFunction("lowfat_oob_check",
            builder.getVoidTy(), builder.getInt32Ty(), builder.getInt8PtrTy(),
            builder.getInt64Ty(), builder.getInt8PtrTy(), nullptr);
        builder.CreateCall(BoundsCheck,
            {builder.getInt32(info), TPtr, Size, BasePtr});
    }    
    // 对任意的指针加 屏蔽size的操作，假设指针是存在较后的这个操作数里的
    if(dyn_cast<StoreInst>(I) || dyn_cast<LoadInst>(I)) {
            if(info != LOWFAT_OOB_ERROR_ESCAPE_STORE) {

                TPtr = builder.CreateBitCast(TPtr, builder.getInt64Ty());
                TPtr = builder.CreateAnd(TPtr,0x03FFFFFFFFFFFFFF);
                TPtr = builder.CreateBitCast(TPtr, Ptr->getType());
                // auto OI = I->op_begin();
                // OI++;
                // // if(OI != I->op_end() && (*OI)->getType()->getTypeID () == 15)
                //     *OI = TPtr;
                
                for (auto OI = I->op_end()-1, OE = I->op_begin(); OI >= OE; --OI) {
                    if((*OI)->getType()->getTypeID () == 15) {
                        *OI = TPtr;
                        break;
                    }
                }
            }
            
    } else if (MemSetInst *MI = dyn_cast<MemSetInst>(I)) {
        TPtr = builder.CreateBitCast(TPtr, builder.getInt64Ty());
        TPtr = builder.CreateAnd(TPtr,0x03FFFFFFFFFFFFFF);
        Value *mem_size = MI->getOperand(2);
        TPtr = builder.CreateSub(TPtr,mem_size);
        TPtr = builder.CreateBitCast(TPtr, Ptr->getType());

        auto OI = MI->op_begin();
        *OI = TPtr;
    } else if (MemTransferInst *MI = dyn_cast<MemTransferInst>(I)) {
        TPtr = builder.CreateBitCast(TPtr, builder.getInt64Ty());
        TPtr = builder.CreateAnd(TPtr,0x03FFFFFFFFFFFFFF);
        Value *mem_size = MI->getOperand(2);
        TPtr = builder.CreateSub(TPtr,mem_size);
        TPtr = builder.CreateBitCast(TPtr, Ptr->getType());

        if(info == LOWFAT_OOB_ERROR_MEMCPY_ONE) {
            auto OI = MI->op_begin();
            *OI = TPtr;
        } else if(info == LOWFAT_OOB_ERROR_MEMCPY_TWO) {
            auto OI = MI->op_begin();
            OI++;
            *OI = TPtr;
        }
    } 
    // else if (InsertElementInst *Insert = dyn_cast<InsertElementInst>(I)) {
    //     TPtr = builder.CreateBitCast(TPtr, builder.getInt64Ty());
    //     TPtr = builder.CreateAnd(TPtr,0x03FFFFFFFFFFFFFF);
    //     TPtr = builder.CreateBitCast(TPtr, Ptr->getType());
    //     auto OI = Insert->op_begin();
    //     OI++;
    //     *OI = TPtr;
    // }
    
}

/*
 * Replace unsafe library functions.
 */
#include <malloc.h>
#define STRING(a)   STRING2(a)
#define STRING2(a)  #a
#define REPLACE2(M, N, alloc)                                           \
    do {                                                                \
        if (Function *F0 = (M)->getFunction(N)) {                       \
            Value *F1 = (M)->getOrInsertFunction("minifat_" N,          \
                F0->getFunctionType());                                 \
            F0->replaceAllUsesWith(F1);                                 \
            Function *F2 = dyn_cast<Function>(F1);                      \
            if ((alloc) && F2 != nullptr) {                             \
                F2->setDoesNotAlias(0);                                 \
                F2->setDoesNotThrow();                                  \
                F2->addAttribute(0, Attribute::NonNull);                \
            }                                                           \
        }                                                               \
    } while (false);
#define REPLACE(M, F, alloc)      REPLACE2(M, STRING(F), alloc)
#define REPLACE_SPECIAL(M, N,NN, alloc)                                 \
    do {                                                                \
        if (Function *F0 = (M)->getFunction(N)) {                       \
            Value *F1 = (M)->getOrInsertFunction(NN,                    \
                F0->getFunctionType());                                 \
            F0->replaceAllUsesWith(F1);                                 \
            Function *F2 = dyn_cast<Function>(F1);                      \
            if ((alloc) && F2 != nullptr) {                             \
                F2->setDoesNotAlias(0);                                 \
                F2->setDoesNotThrow();                                  \
                F2->addAttribute(0, Attribute::NonNull);                \
            }                                                           \
        }                                                               \
    } while (false);


static void replaceUnsafeLibFuncs(Module *M)
{
    REPLACE(M, memset, false);
    REPLACE(M, memcpy, false);
    REPLACE(M, memmove, false);

    if (option_no_replace_malloc)
        return;

    REPLACE(M, malloc, true);
    REPLACE(M, free, true);
    REPLACE(M, calloc, true);
    REPLACE(M, realloc, false);

    REPLACE(M, posix_memalign, false);
    REPLACE(M, aligned_alloc, true);
    REPLACE(M, valloc, true);
    REPLACE(M, memalign, true);
    REPLACE(M, pvalloc, true);

    REPLACE(M, strdup, true);
    REPLACE(M, strndup, true);

    REPLACE2(M, "_Znwm", true);                 // C++ new
    REPLACE2(M, "_Znam", true);                 // C++ new[]
    REPLACE2(M, "_ZdlPv", false);               // C++ delete
    REPLACE2(M, "_ZdaPv", false);               // C++ delete[]
    REPLACE2(M, "_ZnwmRKSt9nothrow_t", true);   // C++ new nothrow
    REPLACE2(M, "_ZnamRKSt9nothrow_t", true);   // C++ new[] nothrow

    // REPLACE(M, memalign, false);
    // REPLACE(M, posix_memalign, false);
    // REPLACE(M, valloc, false);
    // REPLACE(M, pvalloc, false);
    // REPLACE(M, free, false);
    REPLACE(M, mmap, true);
    REPLACE(M, mmap64, true);
    REPLACE(M, mremap, true);
    REPLACE(M, mprotect, true);
    REPLACE(M, madvise, true);
    REPLACE(M, mincore, true);
    REPLACE(M, munmap, true);
    REPLACE(M, munmap64, true);
    // REPLACE(M, memcpy, true);
    // REPLACE(M, memmove, true);
    // REPLACE(M, memset, true);
    REPLACE(M, bzero, true);
    REPLACE(M, bcmp, true);
    REPLACE(M, bcopy, true);
    REPLACE(M, memccpy, true);
    REPLACE(M, memchr, true);
    REPLACE(M, memcmp, true);
    REPLACE(M, memmem, true);
    REPLACE(M, mempcpy, true);
    REPLACE(M, memrchr, true);
    REPLACE(M, index, true);
    REPLACE(M, rindex, true);
    REPLACE(M, stpcpy, true);
    REPLACE(M, stpncpy, true);
    REPLACE(M, strcasecmp, true);
    REPLACE(M, strcasestr, true);
    REPLACE(M, strcat, true);
    REPLACE(M, strchr, true);
    REPLACE(M, strchrnul, true);
    REPLACE(M, strcmp, true);
    REPLACE(M, strcpy, true);
    REPLACE(M, strcspn, true);
    REPLACE(M, __sgxbounds_memdup, true);
    REPLACE(M, __sgxbounds_strdup, true);
    REPLACE(M, strdup, true);
    REPLACE(M, strerror, true);
    REPLACE(M, strerror_r, true);
    REPLACE(M, __xpg_strerror_r, true);
    REPLACE(M, strlcat, true);
    REPLACE(M, strlcpy, true);
    REPLACE(M, strlen, true);
    REPLACE(M, strncasecmp, true);
    REPLACE(M, strncat, true);
    REPLACE(M, strncmp, true);
    REPLACE(M, strncpy, true);
    REPLACE(M, strndup, true);
    REPLACE(M, strnlen, true);
    REPLACE(M, strpbrk, true);
    REPLACE(M, strrchr, true);
    REPLACE(M, strsep, true);
    REPLACE(M, strsignal, true);
    REPLACE(M, strspn, true);
    REPLACE(M, strstr, true);
    REPLACE(M, strtok, true);
    REPLACE(M, strtok_r, true);
    REPLACE(M, strverscmp, true);
    REPLACE(M, swab, true);
    REPLACE(M, open, true);
    REPLACE(M, open64, true);
    REPLACE(M, openat, true);
    REPLACE(M, openat64, true);
    REPLACE(M, creat, true);
    REPLACE(M, creat64, true);
    REPLACE(M, access, true);
    REPLACE(M, acct, true);
    REPLACE(M, chdir, true);
    REPLACE(M, chown, true);
    REPLACE(M, lchown, true);
    REPLACE(M, ctermid, true);
    REPLACE(M, faccessat, true);
    REPLACE(M, fchownat, true);
    REPLACE(M, getgroups, true);
    REPLACE(M, gethostname, true);
    REPLACE(M, getlogin, true);
    REPLACE(M, getlogin_r, true);
    REPLACE(M, link, true);
    REPLACE(M, linkat, true);
    REPLACE(M, pipe, true);
    REPLACE(M, pipe2, true);
    REPLACE(M, pread, true);
    REPLACE(M, pread64, true);
    REPLACE(M, preadv, true);
    REPLACE(M, preadv64, true);
    REPLACE(M, pwrite, true);
    REPLACE(M, pwrite64, true);
    REPLACE(M, write, true);
    REPLACE(M, pwritev, true);
    REPLACE(M, pwritev64, true);
    REPLACE(M, writev, true);
    REPLACE(M, read, true);
    REPLACE(M, readlink, true);
    REPLACE(M, readlinkat, true);
    REPLACE(M, readv, true);
    REPLACE(M, renameat, true);
    REPLACE(M, rmdir, true);
    REPLACE(M, symlink, true);
    REPLACE(M, symlinkat, true);
    REPLACE(M, truncate, true);
    REPLACE(M, truncate64, true);
    REPLACE(M, ttyname, true);
    REPLACE(M, ttyname_r, true);
    REPLACE(M, unlink, true);
    REPLACE(M, unlinkat, true);
    REPLACE(M, fdopen, true);
    REPLACE(M, fgetln, true);
    REPLACE(M, fmemopen, true);
    REPLACE(M, fopen, true);
    REPLACE(M, fopen64, true);
    REPLACE(M, fread, true);
    REPLACE(M, fread_unlocked, true);
    REPLACE(M, freopen, true);
    REPLACE(M, freopen64, true);
    REPLACE(M, fwrite, true);
    REPLACE(M, fwrite_unlocked, true);
    REPLACE(M, getdelim, true);
    REPLACE(M, __getdelim, true);
    REPLACE(M, getline, true);
    REPLACE(M, open_memstream, true);
    REPLACE(M, perror, true);
    REPLACE(M, popen, true);
    REPLACE(M, remove, true);
    REPLACE(M, rename, true);
    REPLACE(M, setbuf, true);
    REPLACE(M, setbuffer, true);
    REPLACE(M, setvbuf, true);
    REPLACE(M, tempnam, true);
    REPLACE(M, tmpnam, true);
    REPLACE(M, scanf, true);
    REPLACE(M, fscanf, true);
    REPLACE(M, vfscanf, true);
    REPLACE(M, vscanf, true);
    REPLACE(M, vsscanf, true);
    REPLACE(M, sscanf, true);
    REPLACE(M, asprintf, true);
    REPLACE(M, vasprintf, true);
    REPLACE(M, dprintf, true);
    REPLACE(M, vdprintf, true);
    REPLACE(M, fprintf, true);
    REPLACE(M, vfprintf, true);
    REPLACE(M, snprintf, true);
    REPLACE(M, sprintf, true);
    REPLACE(M, vprintf, true);
    REPLACE(M, vsnprintf, true);
    REPLACE(M, vsprintf, true);
    REPLACE(M, printf, true);
    REPLACE(M, puts, true);
    REPLACE(M, fputs, true);
    REPLACE(M, fputs_unlocked, true);
    REPLACE(M, gets, true);
    REPLACE(M, fgets, true);
    REPLACE(M, fgets_unlocked, true);
    REPLACE(M, atoi, true);
    REPLACE(M, atof, true);
    REPLACE(M, atol, true);
    REPLACE(M, qsort_cmp, true);
    REPLACE(M, qsort, true);
    REPLACE(M, strtof, true);
    REPLACE(M, strtod, true);
    REPLACE(M, strtold, true);
    REPLACE(M, strtof_l, true);
    REPLACE(M, strtod_l, true);
    REPLACE(M, strtold_l, true);
    REPLACE(M, strtoul, true);
    REPLACE(M, strtoull, true);
    REPLACE(M, gcvt, true);
    REPLACE(M, ecvt, true);
    REPLACE(M, fcvt, true);
    REPLACE(M, asctime, true);
    REPLACE(M, asctime_r, true);
    REPLACE(M, clock_getcpuclockid, true);
    REPLACE(M, clock_getres, true);
    REPLACE(M, clock_gettime, true);
    REPLACE(M, clock_nanosleep, true);
    REPLACE(M, clock_settime, true);
    REPLACE(M, ctime, true);
    REPLACE(M, ctime_r, true);
    REPLACE(M, ftime, true);
    REPLACE(M, getdate, true);
    REPLACE(M, gettimeofday, true);
    REPLACE(M, gmtime, true);
    REPLACE(M, gmtime_r, true);
    REPLACE(M, localtime, true);
    REPLACE(M, localtime_r, true);
    REPLACE(M, mktime, true);
    REPLACE(M, nanosleep, true);
    REPLACE(M, strftime, true);
    REPLACE(M, strftime_l, true);
    REPLACE(M, strptime, true);
    REPLACE(M, time, true);
    REPLACE(M, timegm, true);
    REPLACE(M, timer_create, true);
    REPLACE(M, timer_gettime, true);
    REPLACE(M, timer_settime, true);
    REPLACE(M, times, true);
    REPLACE(M, timespec_get, true);
    REPLACE(M, utime, true);
    REPLACE(M, getenv, true);
    REPLACE(M, putenv, true);
    REPLACE(M, setenv, true);
    REPLACE(M, unsetenv, true);
    REPLACE(M, chmod, true);
    REPLACE(M, fchmodat, true);
    REPLACE(M, fstat, true);
    REPLACE(M, fstat64, true);
    REPLACE(M, fstatat, true);
    REPLACE(M, fstatat64, true);
    REPLACE(M, futimens, true);
    REPLACE(M, futimesat, true);
    REPLACE(M, lchmod, true);
    REPLACE(M, lstat, true);
    REPLACE(M, lstat64, true);
    REPLACE(M, mkdir, true);
    REPLACE(M, mkdirat, true);
    REPLACE(M, mkfifo, true);
    REPLACE(M, mkfifoat, true);
    REPLACE(M, mknod, true);
    REPLACE(M, mknodat, true);
    REPLACE(M, stat, true);
    REPLACE(M, stat64, true);
    REPLACE(M, statfs, true);
    REPLACE(M, statfs64, true);
    REPLACE(M, fstatfs, true);
    REPLACE(M, fstatfs64, true);
    REPLACE(M, statvfs, true);
    REPLACE(M, statvfs64, true);
    REPLACE(M, fstatvfs, true);
    REPLACE(M, fstatvfs64, true);
    REPLACE(M, utimensat, true);
    REPLACE(M, __cxa_atexit, true);
    REPLACE(M, __assert_fail, true);
    REPLACE(M, erand48, true);
    REPLACE(M, lcong48, true);
    REPLACE(M, nrand48, true);
    REPLACE(M, jrand48, true);
    REPLACE(M, rand_r, true);
    REPLACE(M, seed48, true);
    REPLACE(M, getdents, true);
    REPLACE(M, getdents64, true);
    REPLACE(M, opendir, true);
    REPLACE(M, readdir, true);
    REPLACE(M, readdir64, true);
    REPLACE(M, readdir_r, true);
    REPLACE(M, readdir64_r, true);
    REPLACE(M, readdir, true);
    REPLACE(M, setjmp, true);
    REPLACE(M, longjmp, true);
    REPLACE(M, a64l, true);
    REPLACE(M, l64a, true);
    REPLACE(M, basename, true);
    REPLACE(M, dirname, true);
    REPLACE(M, get_current_dir_name, true);
    REPLACE(M, getdomainname, true);
    REPLACE(M, getopt, true);
    REPLACE(M, getopt_long, true);
    REPLACE(M, getopt_long_only, true);
    REPLACE(M, getresgid, true);
    REPLACE(M, getresuid, true);
    REPLACE(M, getrlimit, true);
    REPLACE(M, getrlimit64, true);
    REPLACE(M, getrusage, true);
    REPLACE(M, getsubopt, true);
    REPLACE(M, initgroups, true);
    REPLACE(M, setmntent, true);
    REPLACE(M, getmntent_r, true);
    REPLACE(M, getmntent, true);
    REPLACE(M, addmntent, true);
    REPLACE(M, hasmntopt, true);
    REPLACE(M, nftw_fn, true);
    REPLACE(M, nftw, true);
    REPLACE(M, nftw64, true);
    REPLACE(M, realpath, true);
    REPLACE(M, setdomainname, true);
    REPLACE(M, setrlimit, true);
    REPLACE(M, setrlimit64, true);
    REPLACE(M, openlog, true);
    REPLACE(M, syslog, true);
    REPLACE(M, vsyslog, true);
    REPLACE(M, uname, true);
    REPLACE(M, ioctl, true);
    REPLACE(M, poll, true);
    REPLACE(M, pselect, true);
    REPLACE(M, select, true);
    REPLACE(M, pthread_attr_getdetachstate, true);
    REPLACE(M, pthread_attr_getguardsize, true);
    REPLACE(M, pthread_attr_getinheritsched, true);
    REPLACE(M, pthread_attr_getschedparam, true);
    REPLACE(M, pthread_attr_getschedpolicy, true);
    REPLACE(M, pthread_attr_getscope, true);
    REPLACE(M, pthread_attr_getstack, true);
    REPLACE(M, pthread_attr_getstacksize, true);
    REPLACE(M, pthread_barrierattr_getpshared, true);
    REPLACE(M, pthread_condattr_getclock, true);
    REPLACE(M, pthread_condattr_getpshared, true);
    REPLACE(M, pthread_mutexattr_getprotocol, true);
    REPLACE(M, pthread_mutexattr_getpshared, true);
    REPLACE(M, pthread_mutexattr_getrobust, true);
    REPLACE(M, pthread_mutexattr_gettype, true);
    REPLACE(M, pthread_rwlockattr_getpshared, true);
    REPLACE(M, pthread_attr_setstack, true);
    REPLACE(M, pthread_cond_timedwait, true);
    // REPLACE(M, pthread_create, true);
    REPLACE(M, pthread_getcpuclockid, true);
    REPLACE(M, pthread_getschedparam, true);
    REPLACE(M, pthread_join, true);
    REPLACE(M, pthread_mutex_getprioceiling, true);
    REPLACE(M, pthread_mutex_setprioceiling, true);
    REPLACE(M, pthread_mutex_timedlock, true);
    REPLACE(M, pthread_rwlock_timedrdlock, true);
    REPLACE(M, pthread_rwlock_timedwrlock, true);
    REPLACE(M, pthread_setcancelstate, true);
    REPLACE(M, pthread_setcanceltype, true);
    REPLACE(M, pthread_setschedparam, true);
    REPLACE(M, pthread_setspecific, true);
    REPLACE(M, pthread_getspecific, true);
    REPLACE(M, sem_getvalue, true);
    REPLACE(M, sem_open, true);
    REPLACE(M, sem_timedwait, true);
    REPLACE(M, sem_unlink, true);
    REPLACE(M, pthread_attr_destroy, true);
    REPLACE(M, pthread_attr_init, true);
    REPLACE(M, pthread_attr_setdetachstate, true);
    REPLACE(M, pthread_attr_setguardsize, true);
    REPLACE(M, pthread_attr_setinheritsched, true);
    REPLACE(M, pthread_attr_setschedparam, true);
    REPLACE(M, pthread_attr_setschedpolicy, true);
    REPLACE(M, pthread_attr_setscope, true);
    REPLACE(M, pthread_attr_setstacksize, true);
    REPLACE(M, pthread_barrierattr_destroy, true);
    REPLACE(M, pthread_barrierattr_init, true);
    REPLACE(M, pthread_barrierattr_setpshared, true);
    REPLACE(M, pthread_barrier_destroy, true);
    REPLACE(M, pthread_barrier_init, true);
    REPLACE(M, pthread_barrier_wait, true);
    REPLACE(M, pthread_condattr_destroy, true);
    REPLACE(M, pthread_condattr_init, true);
    REPLACE(M, pthread_condattr_setclock, true);
    REPLACE(M, pthread_condattr_setpshared, true);
    REPLACE(M, pthread_cond_broadcast, true);
    REPLACE(M, pthread_cond_destroy, true);
    REPLACE(M, pthread_cond_init, true);
    REPLACE(M, pthread_cond_signal, true);
    REPLACE(M, pthread_cond_wait, true);
    REPLACE(M, pthread_getattr_np, true);
    REPLACE(M, pthread_key_create, true);
    REPLACE(M, pthread_mutexattr_destroy, true);
    REPLACE(M, pthread_mutexattr_init, true);
    REPLACE(M, pthread_mutexattr_setprotocol, true);
    REPLACE(M, pthread_mutexattr_setpshared, true);
    REPLACE(M, pthread_mutexattr_setrobust, true);
    REPLACE(M, pthread_mutexattr_settype, true);
    REPLACE(M, pthread_mutex_consistent, true);
    REPLACE(M, pthread_mutex_destroy, true);
    REPLACE(M, pthread_mutex_init, true);
    REPLACE(M, pthread_mutex_lock, true);
    REPLACE(M, pthread_mutex_trylock, true);
    REPLACE(M, pthread_mutex_unlock, true);
    REPLACE(M, pthread_once, true);
    REPLACE(M, pthread_rwlockattr_destroy, true);
    REPLACE(M, pthread_rwlockattr_init, true);
    REPLACE(M, pthread_rwlockattr_setpshared, true);
    REPLACE(M, pthread_rwlock_destroy, true);
    REPLACE(M, pthread_rwlock_init, true);
    REPLACE(M, pthread_rwlock_rdlock, true);
    REPLACE(M, pthread_rwlock_tryrdlock, true);
    REPLACE(M, pthread_rwlock_trywrlock, true);
    REPLACE(M, pthread_rwlock_unlock, true);
    REPLACE(M, pthread_rwlock_wrlock, true);
    REPLACE(M, pthread_sigmask, true);
    REPLACE(M, sem_destroy, true);
    REPLACE(M, sem_init, true);
    REPLACE(M, sem_post, true);
    REPLACE(M, sem_trywait, true);
    REPLACE(M, sem_wait, true);
    REPLACE(M, bind_textdomain_codeset, true);
    REPLACE(M, catgets, true);
    REPLACE(M, catopen, true);
    REPLACE(M, bindtextdomain, true);
    REPLACE(M, dcngettext, true);
    REPLACE(M, dcgettext, true);
    REPLACE(M, dngettext, true);
    REPLACE(M, dgettext, true);
    REPLACE(M, gettext, true);
    REPLACE(M, ngettext, true);
    REPLACE(M, iconv_open, true);
    REPLACE(M, iconv, true);
    REPLACE(M, nl_langinfo_l, true);
    REPLACE(M, nl_langinfo, true);
    REPLACE(M, localeconv, true);
    REPLACE(M, newlocale, true);
    REPLACE(M, setlocale, true);
    REPLACE(M, strcoll_l, true);
    REPLACE(M, strcoll, true);
    REPLACE(M, strfmon_l, true);
    REPLACE(M, strfmon, true);
    REPLACE(M, strxfrm_l, true);
    REPLACE(M, strxfrm, true);
    REPLACE(M, textdomain, true);
    REPLACE(M, wcrtomb, true);
    // REPLACE(M, __errno_location, true);
    REPLACE(M, accept, true);
    REPLACE(M, accept4, true);
    REPLACE(M, bind, true);
    REPLACE(M, connect, true);
    REPLACE(M, gethostent, true);
    REPLACE(M, getaddrinfo, true);
    REPLACE(M, freeaddrinfo, true);
    REPLACE(M, gai_strerror, true);
    REPLACE(M, gethostbyaddr, true);
    REPLACE(M, gethostbyaddr_r, true);
    REPLACE(M, gethostbyname, true);
    REPLACE(M, gethostbyname2, true);
    REPLACE(M, gethostbyname2_r, true);
    REPLACE(M, gethostbyname_r, true);
    REPLACE(M, freeifaddrs, true);
    REPLACE(M, getifaddrs, true);
    REPLACE(M, getnameinfo, true);
    REPLACE(M, getpeername, true);
    REPLACE(M, getservbyname, true);
    REPLACE(M, getservbyname_r, true);
    REPLACE(M, getservbyport, true);
    REPLACE(M, getservbyport_r, true);
    REPLACE(M, getsockname, true);
    REPLACE(M, getsockopt, true);
    // REPLACE(M, __h_errno_location, true);
    REPLACE(M, herror, true);
    REPLACE(M, hstrerror, true);
    REPLACE(M, if_freenameindex, true);
    REPLACE(M, if_nameindex, true);
    REPLACE(M, if_indextoname, true);
    REPLACE(M, if_nametoindex, true);
    REPLACE(M, inet_addr, true);
    REPLACE(M, inet_aton, true);
    REPLACE(M, inet_network, true);
    REPLACE(M, inet_ntoa, true);
    REPLACE(M, inet_ntop, true);
    REPLACE(M, inet_pton, true);
    REPLACE(M, getnetbyaddr, true);
    REPLACE(M, getnetbyname, true);
    REPLACE(M, getprotoent, true);
    REPLACE(M, getprotobyname, true);
    REPLACE(M, getprotobynumber, true);
    REPLACE(M, recv, true);
    REPLACE(M, recvfrom, true);
    REPLACE(M, recvmsg, true);
    REPLACE(M, send, true);
    REPLACE(M, sendmsg, true);
    REPLACE(M, sendto, true);
    REPLACE(M, getservent, true);
    REPLACE(M, setsockopt, true);
    REPLACE(M, socketpair, true);
    REPLACE(M, epoll_ctl, true);
    REPLACE(M, epoll_wait, true);
    REPLACE(M, epoll_pwait, true);
    REPLACE(M, sendfile, true);
    REPLACE(M, mkdtemp, true);
    REPLACE(M, mkostemp, true);
    REPLACE(M, mkostemp64, true);
    REPLACE(M, mkostemps, true);
    REPLACE(M, mkostemps64, true);
    REPLACE(M, mkstemp, true);
    REPLACE(M, mkstemp64, true);
    REPLACE(M, mkstemps, true);
    REPLACE(M, mkstemps64, true);
    REPLACE(M, mktemp, true);
    REPLACE(M, fgetgrent, true);
    REPLACE(M, fgetpwent, true);
    REPLACE(M, fgetspent, true);
    REPLACE(M, getgrent, true);
    REPLACE(M, getgrgid, true);
    REPLACE(M, getgrnam, true);
    REPLACE(M, getgrouplist, true);
    REPLACE(M, getgrnam_r, true);
    REPLACE(M, getgrgid_r, true);
    REPLACE(M, getpwent, true);
    REPLACE(M, getpwuid, true);
    REPLACE(M, getpwnam, true);
    REPLACE(M, getpwnam_r, true);
    REPLACE(M, getpwuid_r, true);
    REPLACE(M, getspnam, true);
    REPLACE(M, getspnam_r, true);
    REPLACE(M, putgrent, true);
    REPLACE(M, putpwent, true);
    REPLACE(M, putspent, true);
    REPLACE(M, modf, true);
    REPLACE(M, frexp, true);
    REPLACE(M, getitimer, true);
    REPLACE(M, psiginfo, true);
    REPLACE(M, psignal, true);
    REPLACE(M, setitimer, true);
    REPLACE(M, sigaction, true);
    REPLACE(M, sigaddset, true);
    REPLACE(M, sigaltstack, true);
    REPLACE(M, sigandset, true);
    REPLACE(M, sigdelset, true);
    REPLACE(M, sigemptyset, true);
    REPLACE(M, sigfillset, true);
    REPLACE(M, sigisemptyset, true);
    REPLACE(M, sigismember, true);
    REPLACE(M, sigsetjmp, true);
    REPLACE(M, siglongjmp, true);
    REPLACE(M, sigorset, true);
    REPLACE(M, sigpending, true);
    REPLACE(M, sigprocmask, true);
    REPLACE(M, sigsuspend, true);
    REPLACE(M, sigwait, true);
    REPLACE(M, sigtimedwait, true);
    REPLACE(M, sigwaitinfo, true);
    REPLACE(M, semop, true);
    REPLACE(M, semtimedop, true);
    REPLACE(M, mbtowc, true);
    REPLACE(M, mblen, true);
    REPLACE(M, wcstombs, true);
    REPLACE(M, mbstowcs, true);

    REPLACE_SPECIAL(M, "__isoc99_sscanf", "minifat_sscanf",true)

}

/*
 * Local definitions of LowFat functions.  See the corresponding definitions
 * from lowfat.c/lowfat.h for a human-readable C version.  Note that LowFat
 * options are only applied to the local definitions, and not the library
 * versions.
 */
static void addLowFatFuncs(Module *M)
{
    Function *F = M->getFunction("lowfat_base");
//     if (F != nullptr)
//     {
//         BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);
//         IRBuilder<> builder(Entry);

//         Value *Ptr = &F->getArgumentList().front();
//         //  取消掉我们指针的影响
//         Ptr = builder.CreateAnd(Ptr,0x03FFFFFFFFFFFFFF);
//         Value *Magics = builder.CreateIntToPtr(
//             builder.getInt64((uint64_t)_LOWFAT_MAGICS),
//             builder.getInt64Ty()->getPointerTo());
//         Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
//         Value *Idx = builder.CreateLShr(IPtr,
//             builder.getInt64(LOWFAT_REGION_SIZE_SHIFT));
//         Value *MagicPtr = builder.CreateGEP(Magics, Idx);
//         Value *Magic = builder.CreateAlignedLoad(MagicPtr, sizeof(size_t));
// #if LOWFAT_IS_POW2
//         Value *IBasePtr = builder.CreateAnd(IPtr, Magic);
// #else
//         Value *IPtr128 = builder.CreateZExt(IPtr, builder.getIntNTy(128));
//         Value *Magic128 = builder.CreateZExt(Magic, builder.getIntNTy(128));
//         Value *Tmp128 = builder.CreateMul(IPtr128, Magic128);
//         Tmp128 = builder.CreateLShr(Tmp128, 64);
//         Value *ObjIdx = builder.CreateTrunc(Tmp128, builder.getInt64Ty());
//         Value *Sizes = builder.CreateIntToPtr(
//             builder.getInt64((uint64_t)_LOWFAT_SIZES),
//             builder.getInt64Ty()->getPointerTo());
//         Value *SizePtr = builder.CreateGEP(Sizes, Idx);
//         Value *Size = builder.CreateAlignedLoad(SizePtr, sizeof(size_t));
//         Value *IBasePtr = builder.CreateMul(ObjIdx, Size);
// #endif
//         Value *BasePtr = builder.CreateIntToPtr(IBasePtr,
//             builder.getInt8PtrTy());
//         builder.CreateRet(BasePtr);
 
//         F->setOnlyReadsMemory();
//         F->setDoesNotThrow();
//         F->setLinkage(GlobalValue::InternalLinkage);
//         F->addFnAttr(llvm::Attribute::AlwaysInline);
//     }
    // 添加我们自己的实现方式
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);
        
        // 有non-fat操作的
        BasicBlock *Error = BasicBlock::Create(M->getContext(), "", F);
        BasicBlock *Right = BasicBlock::Create(M->getContext(), "", F);
        // BasicBlock *Stack  = BasicBlock::Create(M->getContext(), "", F);
        // BasicBlock *Heap = BasicBlock::Create(M->getContext(), "", F);
        IRBuilder<> builder(Entry);

        Value *Ptr = &F->getArgumentList().front();
        Ptr = builder.CreateBitCast(Ptr, builder.getInt64Ty());
        Value *size_base = builder.CreateAnd(Ptr,0xFC00000000000000);
        size_base = builder.CreateLShr(size_base,58);
        // Value *size = builder.CreateShl(builder.getInt64(1),size_base);
        Value *Eql = builder.CreateICmpEQ(size_base,builder.getInt64(0));
        builder.CreateCondBr(Eql, Error, Right);

        IRBuilder<> builder2(Error);
        Value* NULL_RETURN = builder2.getInt64(0xFFFFFFFFFFFFFFFF);
        NULL_RETURN = builder2.CreateBitCast(NULL_RETURN,builder2.getInt8PtrTy());
        builder2.CreateRet(NULL_RETURN);
        

        IRBuilder<> builder3(Right);
        Value *mask = builder3.CreateShl(builder3.getInt64(0xFFFFFFFFFFFFFFFF),size_base);
        Value *BasePtr = builder3.CreateAnd(mask,Ptr);
        BasePtr = builder3.CreateBitCast(BasePtr,builder3.getInt8PtrTy());
        builder3.CreateRet(BasePtr);


        // IRBuilder<> builder(Entry);

        // Value *Ptr = &F->getArgumentList().front();
        // Ptr = builder.CreateBitCast(Ptr, builder.getInt64Ty());
        // Value *size_base = builder.CreateAnd(Ptr,0xFC00000000000000);
        // size_base = builder.CreateLShr(size_base,58);
        // Value *mask = builder.CreateShl(builder.getInt64(0xFFFFFFFFFFFFFFFF),size_base);
        // Value *BasePtr = builder.CreateAnd(mask,Ptr);
        // BasePtr = builder.CreateBitCast(BasePtr,builder.getInt8PtrTy());
        // builder.CreateRet(BasePtr);
        
        // 特定时期的某个中间版本，已经不需要
//         Value *Cmp = builder.CreateICmpEQ(size, builder.getInt64(1));
//         Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
//         builder.CreateCondBr(Cmp, Stack, Heap);
//         // stack分支
//         IRBuilder<> builder2(Stack);
//         Value *Magics = builder2.CreateIntToPtr(
//             builder2.getInt64((uint64_t)_LOWFAT_MAGICS),
//             builder2.getInt64Ty()->getPointerTo());
//         Value *IPtr = builder2.CreatePtrToInt(Ptr, builder2.getInt64Ty());
//         Value *Idx = builder2.CreateLShr(IPtr,
//             builder2.getInt64(LOWFAT_REGION_SIZE_SHIFT));
//         Value *MagicPtr = builder2.CreateGEP(Magics, Idx);
//         Value *Magic = builder2.CreateAlignedLoad(MagicPtr, sizeof(size_t));
// #if LOWFAT_IS_POW2
//         Value *IBasePtr = builder2.CreateAnd(IPtr, Magic);
// #else
//         Value *IPtr128 = builder2.CreateZExt(IPtr, builder2.getIntNTy(128));
//         Value *Magic128 = builder2.CreateZExt(Magic, builder2.getIntNTy(128));
//         Value *Tmp128 = builder2.CreateMul(IPtr128, Magic128);
//         Tmp128 = builder2.CreateLShr(Tmp128, 64);
//         Value *ObjIdx = builder2.CreateTrunc(Tmp128, builder2.getInt64Ty());
//         Value *Sizes = builder2.CreateIntToPtr(
//             builder2.getInt64((uint64_t)_LOWFAT_SIZES),
//             builder2.getInt64Ty()->getPointerTo());
//         Value *SizePtr = builder2.CreateGEP(Sizes, Idx);
//         Value *Size = builder2.CreateAlignedLoad(SizePtr, sizeof(size_t));
//         Value *IBasePtr = builder2.CreateMul(ObjIdx, Size);
// #endif
//         Value *BasePtr1 = builder2.CreateIntToPtr(IBasePtr,
//             builder2.getInt8PtrTy());
//         builder2.CreateRet(BasePtr1);

//         // heap分支
//         IRBuilder<> builder3(Heap);
//         Value *mask = builder3.CreateLShr(builder3.getInt64(0xFFFFFFFFFFFFFFFF),size);
//         Value *BasePtr2 = builder3.CreateAnd(mask,Ptr);
//         builder3.CreateRet(BasePtr2);
 
        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_oob_check");
    if (F != nullptr)
    {
        BasicBlock *Entry  = BasicBlock::Create(M->getContext(), "", F);
        BasicBlock *Error  = BasicBlock::Create(M->getContext(), "", F);
        BasicBlock *Return = BasicBlock::Create(M->getContext(), "", F);
        
        // 多一次判断时使用
        BasicBlock *NullReturn = BasicBlock::Create(M->getContext(), "", F);
        BasicBlock *NullGo = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        auto i = F->getArgumentList().begin();
        Value *Info = &(*(i++));
        Value *Ptr = &(*(i++));
        Value *AccessSize = &(*(i++));
        Value *BasePtr = &(*(i++));
        //  取消掉我们指针的影响
        // Ptr = builder.CreateBitCast(Ptr, builder.getInt64Ty());
        // BasePtr = builder.CreateBitCast(BasePtr,builder.getInt64Ty());
        // Ptr = builder.CreateAnd(Ptr,0x03FFFFFFFFFFFFFF);
        // BasePtr = builder.CreateAnd(BasePtr,0x03FFFFFFFFFFFFFF);
        // Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
        // BasePtr = builder.CreateBitCast(BasePtr, builder.getInt8PtrTy());

        Value *IBasePtr = builder.CreatePtrToInt(BasePtr,
            builder.getInt64Ty());

        // 判断是否是non-fat 但是如果是non-fat 按照原本算结果一样
        Value *first_size_base = builder.CreateAnd(IBasePtr,0xFC00000000000000);
        first_size_base = builder.CreateLShr(first_size_base,58);
        Value *Eql = builder.CreateICmpEQ(first_size_base,builder.getInt64(0));
        builder.CreateCondBr(Eql, NullReturn, NullGo);

        IRBuilder<> builder4(NullReturn);
        builder4.CreateRetVoid();

        // Value *Idx = builder.CreateLShr(IBasePtr,
        //     builder.getInt64(LOWFAT_REGION_SIZE_SHIFT));
        // Value *Sizes = builder.CreateIntToPtr(
        //     builder.getInt64((uint64_t)_LOWFAT_SIZES),
        //     builder.getInt64Ty()->getPointerTo());
        // Value *SizePtr = builder.CreateGEP(Sizes, Idx);
        // Value *Size = builder.CreateAlignedLoad(SizePtr, sizeof(size_t));

        // 添加我们的size获取方式 计算size是必须根据baseptr计算，新ptr不计算
        IRBuilder<> builder5(NullGo);
        BasePtr = builder5.CreateBitCast(BasePtr, builder5.getInt64Ty());
        Value *size_base = builder5.CreateAnd(BasePtr,0xFC00000000000000);
        size_base = builder5.CreateLShr(size_base,58);
        Value *Size = builder5.CreateShl(builder5.getInt64(1),size_base);
        BasePtr = builder5.CreateBitCast(BasePtr, builder5.getInt8PtrTy());
        
        // The check is: if (ptr - base > size - sizeof(*ptr)) error();
        Value *IPtr = builder5.CreatePtrToInt(Ptr, builder5.getInt64Ty());
        Value *Diff = builder5.CreateSub(IPtr, IBasePtr);
        Size = builder5.CreateSub(Size, AccessSize);
        Value *Cmp = builder5.CreateICmpUGE(Diff, Size);
        builder5.CreateCondBr(Cmp, Error, Return);


        // // 添加我们的size获取方式 计算size是必须根据baseptr计算，新ptr不计算
        // BasePtr = builder.CreateBitCast(BasePtr, builder.getInt64Ty());
        // Value *size_base = builder.CreateAnd(BasePtr,0xFC00000000000000);
        // size_base = builder.CreateLShr(size_base,58);
        // Value *Size = builder.CreateShl(builder.getInt64(1),size_base);
        // BasePtr = builder.CreateBitCast(BasePtr, builder.getInt8PtrTy());
        
        // // The check is: if (ptr - base > size - sizeof(*ptr)) error();
        // Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
        // Value *Diff = builder.CreateSub(IPtr, IBasePtr);
        // Size = builder.CreateSub(Size, AccessSize);
        // Value *Cmp = builder.CreateICmpUGE(Diff, Size);
        // builder.CreateCondBr(Cmp, Error, Return);
        // Ptr = builder.CreateSelect(Cmp,BasePtr,Ptr);
        
        

        // Value* Result = builder.CreateSelect(Cmp,Error,Warning);
        // builder.CreateCall(Result, {Info, Ptr, BasePtr});
          
        IRBuilder<> builder2(Error);
        if (!option_no_abort)
        {
            Value *Error = M->getOrInsertFunction("lowfat_oob_error",
                builder2.getVoidTy(), builder2.getInt32Ty(),
                builder2.getInt8PtrTy(), builder2.getInt8PtrTy(), nullptr);
            CallInst *Call = builder2.CreateCall(Error, {Info, Ptr, BasePtr});
            Call->setDoesNotReturn();
            builder2.CreateRetVoid();
            builder2.CreateUnreachable();
        }
        else
        {
            Value *Warning = M->getOrInsertFunction("lowfat_oob_warning",
                builder2.getVoidTy(), builder2.getInt32Ty(),
                builder2.getInt8PtrTy(), builder2.getInt8PtrTy(), nullptr);
            builder2.CreateCall(Warning, {Info, Ptr, BasePtr});
            builder2.CreateRetVoid();
        }

        IRBuilder<> builder3(Return);
        builder3.CreateRetVoid();

        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_allocsize");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Idx = &F->getArgumentList().front();
        Value *Sizes = M->getOrInsertGlobal("lowfat_stack_sizes",
            ArrayType::get(builder.getInt64Ty(), 0));
        if (GlobalVariable *Global = dyn_cast<GlobalVariable>(Sizes))
            Global->setConstant(true);
        vector<Value *> Idxs;
        Idxs.push_back(builder.getInt64(0));
        Idxs.push_back(Idx);
        Value *SizePtr = builder.CreateGEP(Sizes, Idxs);
        Value *Size = builder.CreateAlignedLoad(SizePtr, sizeof(size_t));
        builder.CreateRet(Size);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_offset");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Idx = &F->getArgumentList().front();
        Value *Sizes = M->getOrInsertGlobal("lowfat_stack_offsets",
            ArrayType::get(builder.getInt64Ty(), 0));
        if (GlobalVariable *Global = dyn_cast<GlobalVariable>(Sizes))
            Global->setConstant(true);
        vector<Value *> Idxs;
        Idxs.push_back(builder.getInt64(0));
        Idxs.push_back(Idx);
        Value *OffsetPtr = builder.CreateGEP(Sizes, Idxs);
        Value *Offset = builder.CreateAlignedLoad(OffsetPtr, sizeof(ssize_t));
        builder.CreateRet(Offset);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_align");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Ptr = &F->getArgumentList().front();
        Value *Idx = &F->getArgumentList().back();
        Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
        Value *Masks = M->getOrInsertGlobal("lowfat_stack_masks",
            ArrayType::get(builder.getInt64Ty(), 0));
        if (GlobalVariable *Global = dyn_cast<GlobalVariable>(Masks))
            Global->setConstant(true);
        vector<Value *> Idxs;
        Idxs.push_back(builder.getInt64(0));
        Idxs.push_back(Idx);
        Value *MaskPtr = builder.CreateGEP(Masks, Idxs);
        Value *Mask = builder.CreateAlignedLoad(MaskPtr, sizeof(ssize_t));
        IPtr = builder.CreateAnd(IPtr, Mask);
        Ptr = builder.CreateIntToPtr(IPtr, builder.getInt8PtrTy());
        builder.CreateRet(Ptr);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    F = M->getFunction("lowfat_stack_mirror");
    if (F != nullptr)
    {
        BasicBlock *Entry = BasicBlock::Create(M->getContext(), "", F);

        IRBuilder<> builder(Entry);
        Value *Ptr = &F->getArgumentList().front();
        Value *Offset = &F->getArgumentList().back();
        Ptr = builder.CreateGEP(Ptr, Offset);
        builder.CreateRet(Ptr);

        F->setOnlyReadsMemory();
        F->setDoesNotThrow();
        F->setLinkage(GlobalValue::InternalLinkage);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }
}

/*
 * Determine if the given alloca escapes (including if it is used in a bounds
 * check).  If it escapes then the alloca needs to be made non-fat.
 */
static bool doesAllocaEscape(Value *Val, set<Value *> &seen)
{
    if (seen.find(Val) != seen.end())
        return false;
    seen.insert(Val);

    // Sanity check:
    if (Val->getType()->isVoidTy())
    {
        Val->dump();
        Val->getContext().diagnose(LowFatWarning(
            "(BUG) unknown alloca escape"));
        return true;
    }

    for (User *User: Val->users())
    {
        if (isa<ReturnInst>(User))
        {
            // Return local variable = undefined; so does not count
            continue;
        }
        if (isa<LoadInst>(User) || isa<CmpInst>(User))
            continue;
        if (StoreInst *Store = dyn_cast<StoreInst>(User))
        {
            if (Store->getPointerOperand() == Val)
                continue;
            return true;
        }
        if (isa<PtrToIntInst>(User))
        {
            set<Value *> seen;
            if (doesIntEscape(User, seen))
            {
                return true;
            }
            continue;
        }
        if (CallInst *Call = dyn_cast<CallInst>(User))  // Includes OOB-check
        {
            Function *F = Call->getCalledFunction();
            if (F != nullptr && F->doesNotAccessMemory())
                continue;
            return true;
        }
        if (InvokeInst *Invoke = dyn_cast<InvokeInst>(User))
        {
            Function *F = Invoke->getCalledFunction();
            if (F != nullptr && F->doesNotAccessMemory())
                continue;
            return true;
        }
        if (isa<GetElementPtrInst>(User) ||
            isa<BitCastInst>(User) ||
            isa<SelectInst>(User) ||
            isa<PHINode>(User))
        {
            if (doesAllocaEscape(User, seen))
                return true;
            continue;
        }

        // Sanity check:
        User->dump();
        User->getContext().diagnose(LowFatWarning(
            "(BUG) unknown alloca user"));
        return true;
    }

    return false;
}

/*
 * Determine if the given alloca is "interesting" or not.
 */
static bool isInterestingAlloca(Instruction *I)
{
    if (option_no_replace_alloca)
        return false;
    AllocaInst *Alloca = dyn_cast<AllocaInst>(I);
    if (Alloca == nullptr)
        return false;
    set<Value *> seen;
    if (doesAllocaEscape(Alloca, seen))
        return true;
    return false;
}

/*
 * Determine if the given global variant is "interesting" or not.
 */
static bool isInterestingGlobal(GlobalVariable *GV)
{
    if (option_no_replace_globals)
        return false;
    if (GV->hasSection())           // User-declared section
        return false;
    if (GV->getAlignment() > 16)    // User-declared alignment
        return false;
    if (GV->isThreadLocal())        // TLS not supported
        return false;
    switch (GV->getLinkage())
    {
        case GlobalValue::ExternalLinkage:
        case GlobalValue::InternalLinkage:
        case GlobalValue::PrivateLinkage:
        case GlobalValue::WeakAnyLinkage:
        case GlobalValue::WeakODRLinkage:
        case GlobalValue::CommonLinkage:
            break;
        default:
            return false;               // No "fancy" linkage
    }
    return true;
}

/*
 * Convert a global variable into a low-fat-pointer.  This is simple:
 * - Set the global object to be allocSize-aligned; and
 * - Put the object in the low-fat section corresponding for allocSize.
 * The linker will ensure that the sections are placed in the correct low-fat
 * regions.
 */
static void makeGlobalVariableLowFatPtr(Module *M, GlobalVariable *GV)
{
    if (GV->isDeclaration())
        return;
    if (!isInterestingGlobal(GV))
        return;

    // If common linkage is used, then the linker will ignore the "section"
    // attribute and put the object in the .BSS section.  Note that doing this
    // may break some legacy code that depends on common symbols.
    if (GV->hasCommonLinkage())
        GV->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
 
    const DataLayout *DL = &M->getDataLayout();
    Type *Ty = GV->getType();
    PointerType *PtrTy = dyn_cast<PointerType>(Ty);
    assert(PtrTy != nullptr);
    Ty = PtrTy->getElementType();
    size_t size = DL->getTypeAllocSize(Ty);
    size_t idx = clzll(size);
    if (idx <= clzll(LOWFAT_MAX_GLOBAL_ALLOC_SIZE))
    {
        GV->dump();
        GV->getContext().diagnose(LowFatWarning(
            "Global variable cannot be made low-fat (too big)"));
        return;
    }
    size_t align = ~lowfat_stack_masks[idx] + 1;
    if (align > GV->getAlignment())
        GV->setAlignment(align);

    size_t newSize = lowfat_stack_sizes[idx];
    string section("lowfat_section_");
    if (GV->isConstant())
        section += "const_";
    section += to_string(newSize);

    GV->setSection(section);
}

/*
 * Convert an alloca instruction into a low-fat-pointer.  This is a more
 * complicated transformation described in the paper:
 * "Stack Bounds Protection with Low Fat Pointers", in NDSS 2017.
 */
 /*
 * minifat pointer does not need the stack mirror to the heap
 * but needs align and size as 2^n
 */
static void makeAllocaLowFatPtr(Module *M, Instruction *I)
{
    AllocaInst *Alloca = dyn_cast<AllocaInst>(I);
    if (Alloca == nullptr)
        return;

    const DataLayout *DL = &M->getDataLayout();
    Value *Size = Alloca->getArraySize();
    Type *Ty = Alloca->getAllocatedType();
    ConstantInt *ISize = dyn_cast<ConstantInt>(Size);
    Function *F = I->getParent()->getParent();
    auto i = nextInsertPoint(F, Alloca);
    IRBuilder<> builder(i.first, i.second);
    Value *Idx = nullptr, *Offset = nullptr, *AllocedPtr = nullptr;
    Value *NoReplace1 = nullptr, *NoReplace2 = nullptr;
    Value *CastAlloca = nullptr;
    Value *LifetimeSize = nullptr;
    bool delAlloca = false;
    size_t newSize;
//     if (ISize != nullptr)
//     {
//         // Simple+common case: fixed sized alloca:
//         size_t size = DL->getTypeAllocSize(Ty) * ISize->getZExtValue();

//         // STEP (1): Align the stack:
//         size_t idx = clzll(size);
//         if (idx <= clzll(LOWFAT_MAX_STACK_ALLOC_SIZE))
//         {
//             Alloca->dump();
//             Alloca->getContext().diagnose(LowFatWarning(
//                 "Stack allocation cannot be made low-fat (too big)"));
//             return;
//         }
//         ssize_t offset = lowfat_stack_offsets[idx];
//         size_t align = ~lowfat_stack_masks[idx] + 1;
//         if (align > Alloca->getAlignment())
//             Alloca->setAlignment(align);

//         // STEP (2): Adjust the allocation size:
//         newSize = lowfat_stack_sizes[idx];
//         if (newSize != size)
//         {
//             /*
//              * LLVM doubles the allocSz when the object is allocSz-aligned for
//              * some reason (gcc does not seem to do this).  This wastes space
//              * but it does not seem there is anything we can do about it.
//              */
//             LifetimeSize = builder.getInt64(newSize);
//             AllocaInst *NewAlloca = builder.CreateAlloca(
//                 builder.getInt8Ty(), LifetimeSize);
//             NewAlloca->setAlignment(Alloca->getAlignment());
//             AllocedPtr = NewAlloca;
//             delAlloca = true;
//         }
//         else
//             AllocedPtr = builder.CreateBitCast(Alloca, builder.getInt8PtrTy());
//         Offset = builder.getInt64(offset);
//         CastAlloca = AllocedPtr;
//         NoReplace1 = AllocedPtr;
//     }
//     else
//     {
// #ifdef LOWFAT_LEGACY
//         // VLAs are disabled for LEGACY mode due to the alloca(0) problem.
//         return;
// #else
//         // Complex+hard case: variable length stack object (e.g. VLAs)
//         delAlloca = true;

//         // STEP (1): Get the index/offset:
//         Size = builder.CreateMul(builder.getInt64(DL->getTypeAllocSize(Ty)),
//             Size);
//         Constant *C = M->getOrInsertFunction("llvm.ctlz.i64",
//             builder.getInt64Ty(), builder.getInt64Ty(), builder.getInt1Ty(),
//             nullptr);
//         Idx = builder.CreateCall(C, {Size, builder.getInt1(true)});
//         if (CallInst *Call = dyn_cast<CallInst>(Idx))
//             Call->setTailCall(true);
//         C = M->getOrInsertFunction("lowfat_stack_offset",
//             builder.getInt64Ty(), builder.getInt64Ty(), nullptr);
//         Offset = builder.CreateCall(C, {Idx});
//         if (CallInst *Call = dyn_cast<CallInst>(Offset))
//             Call->setTailCall(true);

//         // STEP (2): Get the actual allocation size:
//         C = M->getOrInsertFunction("lowfat_stack_allocsize",
//             builder.getInt64Ty(), builder.getInt64Ty(), nullptr);
//         Size = builder.CreateCall(C, {Idx});
//         if (CallInst *Call = dyn_cast<CallInst>(Size))
//             Call->setTailCall(true);

//         // STEP (3): Create replacement alloca():
//         CastAlloca = builder.CreateAlloca(builder.getInt8Ty(), Size);
//         Value *SP = CastAlloca;     // SP = Stack pointer

//         // STEP (4): Align the stack:
//         C = M->getOrInsertFunction("lowfat_stack_align",
//             builder.getInt8PtrTy(), builder.getInt8PtrTy(),
//             builder.getInt64Ty(), nullptr);
//         SP = builder.CreateCall(C, {SP, Idx});
//         NoReplace1 = SP;
//         if (CallInst *Call = dyn_cast<CallInst>(SP))
//             Call->setTailCall(true);

//         // STEP (5): Save the adjusted stack pointer:
//         C = M->getOrInsertFunction("llvm.stackrestore",
//             builder.getVoidTy(), builder.getInt8PtrTy(), nullptr);
//         Value *_ = builder.CreateCall(C, {SP});
//         if (CallInst *Call = dyn_cast<CallInst>(_))
//             Call->setTailCall(true);

//         AllocedPtr = SP;
// #endif
//     }

//     // STEP (3)/(6): Mirror the pointer into a low-fat region:
//     Value *C = M->getOrInsertFunction("lowfat_stack_mirror",
//         builder.getInt8PtrTy(), builder.getInt8PtrTy(), builder.getInt64Ty(),
//         nullptr);
//     Value *MirroredPtr = builder.CreateCall(C, {AllocedPtr, Offset});
//     NoReplace2 = MirroredPtr;
//     Value *Ptr = builder.CreateBitCast(MirroredPtr, Alloca->getType());
//     Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());

    // minifat pointer的组织形式
    if(ISize != nullptr) {
        size_t size = DL->getTypeAllocSize(Ty) * ISize->getZExtValue();
        newSize = 1 << (64 - clzll(size));

        size_t align = newSize;
        if (align > Alloca->getAlignment())
            Alloca->setAlignment(align);

        if (newSize != size)
        {
            LifetimeSize = builder.getInt64(newSize);
            AllocaInst *NewAlloca = builder.CreateAlloca(
                builder.getInt8Ty(), LifetimeSize);
            NewAlloca->setAlignment(Alloca->getAlignment());
            AllocedPtr = NewAlloca;
            delAlloca = true;
        }
        else
            AllocedPtr = builder.CreateBitCast(Alloca, builder.getInt8PtrTy());
        CastAlloca = AllocedPtr;
        NoReplace1 = AllocedPtr;
    } else {
        delAlloca = true;

        Size = builder.CreateMul(builder.getInt64(DL->getTypeAllocSize(Ty)),
            Size);
        Constant *C = M->getOrInsertFunction("llvm.ctlz.i64",
            builder.getInt64Ty(), builder.getInt64Ty(), builder.getInt1Ty(),
            nullptr);
       
        Value *zero_num = builder.CreateCall(C, {Size, builder.getInt1(true)});
        if (CallInst *Call = dyn_cast<CallInst>(zero_num))
            Call->setTailCall(true);
        // STEP (2): Get the actual allocation size:
        Value *base = builder.CreateSub(builder.getInt64(64),zero_num);
        Size = builder.CreateShl(builder.getInt64(1),base);

        // STEP (3): Create replacement alloca():
        CastAlloca = builder.CreateAlloca(builder.getInt8Ty(), Size);
        Value *SP = CastAlloca;     // SP = Stack pointer

         // STEP (4): Align the stack:
        Value *SPD = builder.CreateBitCast(SP,builder.getInt64Ty());
        SPD = builder.CreateAnd(SPD,Size);
        SP = builder.CreateBitCast(SPD, SP->getType ());
        NoReplace1 = SP;

        // STEP (5): Save the adjusted stack pointer:
        C = M->getOrInsertFunction("llvm.stackrestore",
            builder.getVoidTy(), builder.getInt8PtrTy(), nullptr);
        Value *_ = builder.CreateCall(C, {SP});
        if (CallInst *Call = dyn_cast<CallInst>(_))
            Call->setTailCall(true);

        AllocedPtr = SP;
    }

    // 在给每一个用户之前，把他变成minifat-pointer
    Value *Ptr = builder.CreateBitCast(AllocedPtr, builder.getInt8PtrTy());
    Value *package = M->getOrInsertFunction("minifat_pointer_package",
        builder.getInt8PtrTy(), builder.getInt8PtrTy(), builder.getInt64Ty(),
        nullptr); 
    if(ISize != nullptr)
        Ptr = builder.CreateCall(package, {Ptr, builder.getInt64(newSize)});
    else
        Ptr = builder.CreateCall(package, {Ptr, Size});
    Ptr = builder.CreateBitCast(Ptr, Alloca->getType());
    // AllocedPtr = builder.CreateBitCast(AllocedPtr, Alloca->getType());

    // Replace all uses of `Alloca' with the (now low-fat) `Ptr'.
    // We do not replace lifetime intrinsics nor values used in the
    // construction of the low-fat pointer (NoReplace1, ...).
    vector<User *> replace, lifetimes;
    vector<User *> ls_replace;
    for (User *Usr: Alloca->users())
    {
        if (Usr == NoReplace1 || Usr == NoReplace2)
            continue;
        if (IntrinsicInst *Intr = dyn_cast<IntrinsicInst>(Usr))
        {
            if (Intr->getIntrinsicID() == Intrinsic::lifetime_start ||
                    Intr->getIntrinsicID() == Intrinsic::lifetime_end)
            {
                lifetimes.push_back(Usr);
                continue;
            }
        }
        if (BitCastInst *Cast = dyn_cast<BitCastInst>(Usr))
        {
            for (User *Usr2: Cast->users())
            {
                IntrinsicInst *Intr = dyn_cast<IntrinsicInst>(Usr2);
                if (Intr == nullptr)
                    continue;
                if (Intr->getIntrinsicID() == Intrinsic::lifetime_start ||
                        Intr->getIntrinsicID() == Intrinsic::lifetime_end)
                    lifetimes.push_back(Usr2);
            }
        }
        // if(dyn_cast<LoadInst>(Usr) || dyn_cast<StoreInst>(Usr))
        //     ls_replace.push_back(Usr);
        // else
            replace.push_back(Usr);
    }
    
    for (User *Usr: replace)
        Usr->replaceUsesOfWith(Alloca, Ptr);
    // for (User *Usr: ls_replace)
    //     Usr->replaceUsesOfWith(Alloca, AllocedPtr);

    for (User *Usr: lifetimes)
    {
        // Lifetimes are deleted.  The alternative is to insert the mirroring
        // after the lifetime start, however, this proved too difficult to get
        // working.  One problem is intermediate casts which may be reused.
        if (auto *Lifetime = dyn_cast<Instruction>(Usr))
            Lifetime->eraseFromParent();
    }
    if (delAlloca)
        Alloca->eraseFromParent();
}

/*
 * Blacklist checking.
 */
static bool isBlacklisted(SpecialCaseList *SCL, Module *M)
{
    if (SCL == nullptr)
        return false;
    if (SCL->inSection("src", M->getModuleIdentifier()))
        return true;
    return false;
}
static bool isBlacklisted(SpecialCaseList *SCL, Function *F)
{
    if (SCL == nullptr)
        return false;
    return SCL->inSection("fun", F->getName());
}


/*
* Minifat_Pass
* this function is for some usecases need to mask the ptr
*/
static void maskInst(Instruction *I)
{
    if (I->getMetadata("nosanitize") != nullptr)
        return;
    if (CmpInst  *Cmp = dyn_cast<CmpInst >(I))
    {
        Value *Arg1 = Cmp->getOperand(0);
        Value *Arg2 = Cmp->getOperand(1);

        if (!Arg1->getType()->isPointerTy())
            return;
        
        IRBuilder<> builder(Cmp);
        Value* TArg1 = builder.CreateBitCast(Arg1, builder.getInt64Ty());
        TArg1 = builder.CreateAnd(TArg1,0x03FFFFFFFFFFFFFF);
        TArg1 = builder.CreateBitCast(TArg1, Arg1->getType());
        auto OI = Cmp->op_begin();
        *OI = TArg1;
        
        Value* TArg2 = builder.CreateBitCast(Arg2, builder.getInt64Ty());
        TArg2 = builder.CreateAnd(TArg2,0x03FFFFFFFFFFFFFF);
        TArg2 = builder.CreateBitCast(TArg2, Arg2->getType());
        OI++;
        *OI = TArg2;
        
    }
    else if(CallInst *Call = dyn_cast<CallInst >(I)) {
        Function *F = Call->getCalledFunction();
        if (F != nullptr && F->getName() == "minifat_sscanf") {
            IRBuilder<> builder(Call);
            auto OI = Call->op_begin();
            for (unsigned i = 2; i < Call->getNumArgOperands(); i++)
            {
                Value *Arg = Call->getArgOperand(i);
                Value* TArg = builder.CreateBitCast(Arg, builder.getInt64Ty());
                TArg = builder.CreateAnd(TArg,0x03FFFFFFFFFFFFFF);
                TArg = builder.CreateBitCast(TArg, Arg->getType());

                *(OI+i) = TArg;
                
            }
        }

    }

}


/*
 * LowFat LLVM Pass
 */
namespace
{

struct LowFat : public ModulePass
{
    static char ID;
    LowFat() : ModulePass(ID) { }

    virtual bool runOnModule(Module &M)
    {
        if (option_debug)
        {
            string outName(M.getName());
            outName += ".in.lowfat.ll";
            std::error_code errInfo;
            raw_fd_ostream out(outName.c_str(), errInfo, sys::fs::F_None);
            M.print(out, nullptr);
        }

        // Read the blacklist file (if it exists)
        unique_ptr<SpecialCaseList> Blacklist = nullptr;
        if (option_no_check_blacklist != "-")
        {
            vector<string> paths;
            paths.push_back(option_no_check_blacklist);
            string err;
            Blacklist = SpecialCaseList::create(paths, err);
        }
        if (isBlacklisted(Blacklist.get(), &M))
            return true;

        // PASS (1): Bounds instrumentation
        const TargetLibraryInfo &TLI =
            getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
        const DataLayout *DL = &M.getDataLayout();
        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;
            if (isBlacklisted(Blacklist.get(), &F))
                continue;

            // STEP #1: Find all instructions that we need to instrument:
            Plan plan;
            BoundsInfo boundsInfo;
            for (auto &BB: F)
                for (auto &I: BB)
                    getInterestingInsts(&TLI, DL, boundsInfo, &I, plan);

            // STEP #2: Calculate the base pointers:
            PtrInfo baseInfo;
            for (auto &p: plan)
                (void)calcBasePtr(&TLI, &F, get<1>(p), baseInfo);

            // STEP #3: Add the bounds check:
            for (auto &p: plan)
                insertBoundsCheck(DL, get<0>(p), get<1>(p), get<2>(p),
                    baseInfo);
        }

        // PASS (1a) Stack object lowfatification
        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;

            // STEP #1: Find all interesting allocas:
            vector<Instruction *> allocas;
            for (auto &BB: F)
                for (auto &I: BB)
                    if (isInterestingAlloca(&I))
                        allocas.push_back(&I);

            // STEP #2: Mirror all interesting allocas:
            for (auto *I: allocas)
                makeAllocaLowFatPtr(&M, I);
        }

        // Pass (1b) Global Variable lowfatification
        // if (!option_no_replace_globals)
        //     for (auto &GV: M.getGlobalList())
        //         makeGlobalVariableLowFatPtr(&M, &GV);

        // PASS (2): Replace unsafe library calls
        replaceUnsafeLibFuncs(&M);

        // PASS (3): Add function definitions
        addLowFatFuncs(&M);

        // PASS (4): Optimize lowfat_malloc() calls
        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;
            vector<Instruction *> dels;
            for (auto &BB: F)
                for (auto &I: BB)
                    optimizeMalloc(&M, &I, dels);
            for (auto &I: dels)
                I->eraseFromParent();
        }

        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;
            if (isBlacklisted(Blacklist.get(), &F))
                continue;

            // STEP #1: Find all instructions that we need to instrument:
            for (auto &BB: F)
                for (auto &I: BB)
                    maskInst(&I);
        }


        if (option_debug)
        {
            string outName(M.getName());
            outName += ".out.lowfat.ll";
            std::error_code errInfo;
            raw_fd_ostream out(outName.c_str(), errInfo, sys::fs::F_None);
            M.print(out, nullptr);

            string errs;
            raw_string_ostream rso(errs);
            if (verifyModule(M, &rso))
            {
                fprintf(stderr, "LowFat generated broken IR!\n");
                fprintf(stderr, "%s\n", errs.c_str());
                abort();
            }
        }

        return true;
    }

    /*
     * Analysis usage specification.
     */
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<TargetLibraryInfoWrapperPass>();
    }
};

}

char LowFat::ID = 0;
namespace llvm
{
    ModulePass *createLowFatPass()
    {
        return new LowFat();
    }
}

/*
 * Boilerplate for LowFat.so loadable module.
 */
#ifdef LOWFAT_PLUGIN
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"

static RegisterPass<LowFat> X("lowfat", "LowFat pass");

static void register_pass(const PassManagerBuilder &PMB,
    legacy::PassManagerBase &PM)
{
    PM.add(new LowFat());
}

static RegisterStandardPasses RegisterPass(
    PassManagerBuilder::EP_LoopOptimizerEnd, register_pass);
#endif      /* LOWFAT_PLUGIN */

