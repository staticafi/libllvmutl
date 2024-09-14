#ifndef LLVMUTL_LLVM_UTILS_HPP_INCLUDED
#   define LLVMUTL_LLVM_UTILS_HPP_INCLUDED

#   include <utility/config.hpp>
#   if COMPILER() == COMPILER_VC()
#       pragma warning(push)
#       pragma warning(disable : 4624 4996 4146 4800 4996 4005 4355 4244 4267)
#   endif
#   include <llvm/IR/Instructions.h>
#   include <llvm/IR/Constants.h>
#   if COMPILER() == COMPILER_VC()
#       pragma warning(pop)
#   endif
#   include <string>
#   include <cstdint>


std::string llvm_to_str(llvm::Value const* value);
std::string llvm_to_str(llvm::Type const* type);
inline std::string llvm_to_str(llvm::Constant const* const c) { return llvm_to_str((llvm::Value*)c); }
std::size_t llvm_sizeof(llvm::Type* type, llvm::Module& M);
bool llvm_is_zero(llvm::Value* value);
llvm::Instruction* llvm_constant_expr_to_instruction(llvm::ConstantExpr* expression, llvm::Instruction* succ_instruction = nullptr);
bool llvm_basic_block_contains_intrinsic_before_instruction(
    llvm::BasicBlock const* llvm_block,
    llvm::Intrinsic::ID llvm_intrinsic_id,
    llvm::Instruction const* llvm_instruction
    );
bool llvm_basic_block_contains_intrinsic(llvm::BasicBlock const* llvm_block, llvm::Intrinsic::ID llvm_intrinsic_id);
bool llvm_function_contains_intrinsic(llvm::Function const* llvm_function, llvm::Intrinsic::ID llvm_intrinsic_id);


#endif
