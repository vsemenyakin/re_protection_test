//! Obfusc -- a minimal LLVM 20 new-PM pass plugin for Layer 4 (control-flow /
//! arithmetic obfuscation), loaded into rustc via `-Zllvm-plugins`.
//!
//! It applies, per function, according to a crown/rest policy passed on the LLVM
//! command line (`-Cllvm-args=...` from the RUSTC_WORKSPACE_WRAPPER):
//!
//!   * SUB -- instruction substitution with mixed boolean-arithmetic (MBA)
//!     identities: each integer add/sub/and/or/xor is rewritten into an
//!     equivalent but tangled expression. Run in N rounds, it compounds. This is
//!     the measure Layer 4 cares about most for Layer 3: it smears the per-site
//!     key mixing and the decode XOR so "find the one 64-bit key" does not work.
//!   * BCF -- bogus control flow: each eligible block is guarded by an opaque
//!     predicate (always true, but opaque to the optimizer via a volatile load)
//!     with a dead bogus successor, inflating the CFG.
//!
//! The pass runs at OptimizerLast, so later InstCombine does not undo the MBA.
//! Every rewrite preserves the runtime value, so the behaviour oracle is
//! unchanged.

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Regex.h"
#include "llvm/Transforms/Utils/Local.h" // DemoteRegToStack / DemotePHIToStack

#include <cstdlib>
#include <string>
#include <vector>

using namespace llvm;

// Config comes from the environment, not cl::opt: a `-Zllvm-plugins` plugin is
// loaded *after* rustc has already parsed `-Cllvm-args`, so plugin-registered
// cl::opt options are rejected as "unknown". The env vars are set by the build
// script and inherited by the rustc process, so the pass reads them at run time.
namespace {

struct Config {
  std::string crownRe;
  unsigned subCrown = 0;
  unsigned subRest = 0;
  bool bcf = false;
  bool fla = false;
  bool verbose = false;
};

const Config &config() {
  static Config c = [] {
    Config c;
    if (const char *s = std::getenv("OBF_CROWN"))
      c.crownRe = s;
    if (const char *s = std::getenv("OBF_SUB_CROWN"))
      c.subCrown = std::strtoul(s, nullptr, 10);
    if (const char *s = std::getenv("OBF_SUB_REST"))
      c.subRest = std::strtoul(s, nullptr, 10);
    if (const char *s = std::getenv("OBF_BCF"))
      c.bcf = std::string(s) == "1";
    if (const char *s = std::getenv("OBF_FLA"))
      c.fla = std::string(s) == "1";
    if (const char *s = std::getenv("OBF_VERBOSE"))
      c.verbose = std::string(s) == "1";
    return c;
  }();
  return c;
}

// One round of MBA instruction substitution. Returns true if anything changed.
bool substituteOnce(Function &F) {
  std::vector<BinaryOperator *> ops;
  for (auto &I : instructions(F))
    if (auto *bo = dyn_cast<BinaryOperator>(&I))
      if (bo->getType()->isIntegerTy() &&
          bo->getType()->getIntegerBitWidth() >= 8)
        ops.push_back(bo);

  bool changed = false;
  for (auto *bo : ops) {
    IRBuilder<> B(bo);
    Value *a = bo->getOperand(0), *b = bo->getOperand(1);
    Type *ty = bo->getType();
    Value *r = nullptr;
    switch (bo->getOpcode()) {
    case Instruction::Add: // a+b = (a^b) + 2*(a&b)
      r = B.CreateAdd(B.CreateXor(a, b),
                      B.CreateMul(ConstantInt::get(ty, 2), B.CreateAnd(a, b)));
      break;
    case Instruction::Sub: // a-b = a + ~b + 1
      r = B.CreateAdd(B.CreateAdd(a, B.CreateNot(b)), ConstantInt::get(ty, 1));
      break;
    case Instruction::Xor: // a^b = (a|b) - (a&b)
      r = B.CreateSub(B.CreateOr(a, b), B.CreateAnd(a, b));
      break;
    case Instruction::And: // a&b = (a+b) - (a|b)
      r = B.CreateSub(B.CreateAdd(a, b), B.CreateOr(a, b));
      break;
    case Instruction::Or: // a|b = (a+b) - (a&b)
      r = B.CreateSub(B.CreateAdd(a, b), B.CreateAnd(a, b));
      break;
    default:
      break;
    }
    if (r) {
      bo->replaceAllUsesWith(r);
      bo->eraseFromParent();
      changed = true;
    }
  }
  return changed;
}

// A module-global int the optimizer cannot fold away (read volatile), used to
// build an opaque-but-always-true predicate for BCF.
GlobalVariable *opaqueGlobal(Module &M) {
  const char *name = "obf_opaque";
  if (auto *g = M.getGlobalVariable(name))
    return g;
  Type *i32 = Type::getInt32Ty(M.getContext());
  return new GlobalVariable(M, i32, /*isConstant=*/false,
                            GlobalValue::InternalLinkage,
                            ConstantInt::get(i32, 0), name);
}

// pred = ((y*(y+1)) & 1) == 0  -- always true (product of consecutive ints is
// even), but opaque because y comes from a volatile load.
Value *opaqueTrue(IRBuilder<> &B, Module &M) {
  Type *i32 = Type::getInt32Ty(M.getContext());
  Value *y = B.CreateLoad(i32, opaqueGlobal(M), /*isVolatile=*/true);
  Value *t = B.CreateMul(y, B.CreateAdd(y, ConstantInt::get(i32, 1)));
  Value *lo = B.CreateAnd(t, ConstantInt::get(i32, 1));
  return B.CreateICmpEQ(lo, ConstantInt::get(i32, 0));
}

bool bogusControlFlow(Function &F) {
  Module &M = *F.getParent();
  std::vector<BasicBlock *> blocks;
  for (auto &BB : F)
    blocks.push_back(&BB);

  bool changed = false;
  for (auto *BB : blocks) {
    if (BB->isEHPad() || BB->isLandingPad())
      continue;
    // Need a splittable point with at least a couple of real instructions.
    // LLVM 20: getFirstNonPHIOrDbg() returns an iterator.
    BasicBlock::iterator sp = BB->getFirstNonPHIOrDbg();
    if (sp == BB->end() || sp->isTerminator())
      continue;
    if (std::next(sp) == BB->end())
      continue;

    BasicBlock *real = BB->splitBasicBlock(sp, "obf.real");
    BasicBlock *bog = BasicBlock::Create(M.getContext(), "obf.bog", &F);
    IRBuilder<> bb(bog);
    bb.CreateBr(real);

    // Replace BB's fresh unconditional branch with an opaque conditional.
    BB->getTerminator()->eraseFromParent();
    IRBuilder<> hb(BB);
    Value *pred = opaqueTrue(hb, M);
    hb.CreateCondBr(pred, real, bog);
    changed = true;
  }
  return changed;
}

// Control-flow flattening (FLA). Dissolves the CFG into a dispatcher loop: a
// state variable selects the next block via a switch, and each block ends by
// setting the next state and jumping back to the dispatcher, so the static CFG
// no longer reflects the real control flow.
//
// SSA safety: flattening lets a block be reached from the dispatcher regardless
// of the real predecessor, which would break any value that lives across blocks
// (and any PHI). So we first demote all cross-block values and all PHIs to stack
// slots (reg2mem); after that no non-alloca value crosses a block boundary.
bool flatten(Function &F) {
  // Bail on shapes we do not flatten safely (unwinding / indirect control flow).
  for (auto &BB : F) {
    if (BB.isEHPad())
      return false;
    Instruction *t = BB.getTerminator();
    if (isa<InvokeInst>(t) || isa<IndirectBrInst>(t) || isa<CallBrInst>(t) ||
        isa<ResumeInst>(t) || isa<CatchSwitchInst>(t) || isa<CleanupReturnInst>(t))
      return false;
  }
  if (F.size() < 3)
    return false;

  // reg2mem: snapshot first (we mutate), then demote PHIs and cross-block values.
  std::vector<PHINode *> phis;
  std::vector<Instruction *> cross;
  for (auto &BB : F)
    for (auto &I : BB) {
      if (auto *p = dyn_cast<PHINode>(&I))
        phis.push_back(p);
      else if (!isa<AllocaInst>(&I) && I.isUsedOutsideOfBlock(&BB))
        cross.push_back(&I);
    }
  for (auto *p : phis)
    DemotePHIToStack(p);
  for (auto *i : cross)
    DemoteRegToStack(*i);

  // Make the entry block end in a single unconditional edge: split off its
  // terminator so the rest of the function becomes flattenable blocks.
  BasicBlock *entry = &F.getEntryBlock();
  entry->splitBasicBlock(entry->getTerminator()->getIterator(), "obf.first");

  std::vector<BasicBlock *> blocks;
  for (auto &BB : F)
    if (&BB != entry)
      blocks.push_back(&BB);
  if (blocks.size() < 2)
    return false;

  LLVMContext &C = F.getContext();
  IntegerType *i32 = Type::getInt32Ty(C);
  DenseMap<BasicBlock *, unsigned> id;
  for (unsigned i = 0; i < blocks.size(); ++i)
    id[blocks[i]] = i;

  BasicBlock *first = entry->getSingleSuccessor();
  BranchInst *et = cast<BranchInst>(entry->getTerminator());
  IRBuilder<> eb(et);
  AllocaInst *stateVar = eb.CreateAlloca(i32, nullptr, "obf.state");
  eb.CreateStore(ConstantInt::get(i32, id[first]), stateVar);

  BasicBlock *dispatch = BasicBlock::Create(C, "obf.dispatch", &F);
  BasicBlock *dflt = BasicBlock::Create(C, "obf.default", &F);
  eb.CreateBr(dispatch);
  et->eraseFromParent();

  IRBuilder<> db(dispatch);
  LoadInst *sv = db.CreateLoad(i32, stateVar, "obf.sv");
  SwitchInst *sw = db.CreateSwitch(sv, dflt, blocks.size());
  for (auto *b : blocks)
    sw->addCase(ConstantInt::get(i32, id[b]), b);
  IRBuilder<>(dflt).CreateBr(dispatch);

  // Rewrite each block's terminator to set the next state and loop back.
  for (auto *b : blocks) {
    auto *bi = dyn_cast<BranchInst>(b->getTerminator());
    if (!bi)
      continue; // ret / unreachable / switch left intact (targets still exist)
    IRBuilder<> tb(bi);
    if (bi->isUnconditional()) {
      auto it = id.find(bi->getSuccessor(0));
      if (it == id.end())
        continue;
      tb.CreateStore(ConstantInt::get(i32, it->second), stateVar);
      tb.CreateBr(dispatch);
      bi->eraseFromParent();
    } else {
      auto i0 = id.find(bi->getSuccessor(0));
      auto i1 = id.find(bi->getSuccessor(1));
      if (i0 == id.end() || i1 == id.end())
        continue;
      Value *next = tb.CreateSelect(bi->getCondition(),
                                    ConstantInt::get(i32, i0->second),
                                    ConstantInt::get(i32, i1->second));
      tb.CreateStore(next, stateVar);
      tb.CreateBr(dispatch);
      bi->eraseFromParent();
    }
  }
  return true;
}

struct ObfuscPass : PassInfoMixin<ObfuscPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
      return PreservedAnalyses::all();

    const Config &cfg = config();
    bool crown = false;
    if (!cfg.crownRe.empty()) {
      Regex re(cfg.crownRe);
      crown = re.match(F.getName());
    }
    unsigned rounds = crown ? cfg.subCrown : cfg.subRest;

    bool changed = false;
    for (unsigned i = 0; i < rounds; i++)
      changed |= substituteOnce(F);
    if (crown && cfg.bcf)
      changed |= bogusControlFlow(F);
    if (crown && cfg.fla)
      changed |= flatten(F);

    if (cfg.verbose && changed)
      errs() << "[obfusc] " << (crown ? "crown " : "rest  ") << F.getName()
             << "\n";
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

} // namespace

llvm::PassPluginLibraryInfo getObfuscPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Obfusc", "v0.1", [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel,
                   ThinOrFullLTOPhase) {
                  MPM.addPass(createModuleToFunctionPassAdaptor(ObfuscPass()));
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return getObfuscPluginInfo();
}
