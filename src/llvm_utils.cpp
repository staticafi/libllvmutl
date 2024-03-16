#include <llvmutl/llvm_utils.hpp>
#include <utility/timeprof.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#if COMPILER() == COMPILER_VC()
#    pragma warning(push)
#    pragma warning(disable : 4624 4996 4146 4800 4996 4005 4355 4244 4267)
#endif
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/DebugInfo/DIContext.h>
#if COMPILER() == COMPILER_VC()
#    pragma warning(pop)
#endif


template<typename T>
static std::string __llvm_to_str(T const* const x)
{
    std::string str;
    llvm::raw_string_ostream rso(str);
    x->print(rso);
    return rso.str();
}


std::string llvm_to_str(llvm::Value const* const value)
{
    return __llvm_to_str(value);
}


std::string llvm_to_str(llvm::Type const* const type)
{
    return __llvm_to_str(type);
}


llvm::Type* llvm_deref_if_pointer(llvm::Type* const type)
{
    if (auto ptr = llvm::dyn_cast<llvm::PointerType>(type))
        return ptr->getPointerElementType();
    return type;
}


llvm::Type* llvm_lowered_type(llvm::Value const* value_ptr)
{
    if (auto instruction_ptr = llvm::dyn_cast<llvm::Instruction>(value_ptr))
        switch (instruction_ptr->getOpcode())
        {
        case llvm::Instruction::Load:
        case llvm::Instruction::BitCast:
        case llvm::Instruction::GetElementPtr:
        case llvm::Instruction::Call:
        case llvm::Instruction::Ret:
        case llvm::Instruction::IntToPtr:
            break;
        default:
            return llvm_deref_if_pointer(instruction_ptr->getType());
            break;
        }
    else if (llvm::isa<llvm::GlobalVariable>(value_ptr))
        return llvm_deref_if_pointer(value_ptr->getType());
    return value_ptr->getType();
}


std::size_t llvm_sizeof(llvm::Type* const type, llvm::Module& M)
{
    return M.getDataLayout().getTypeAllocSize(type);
}


bool llvm_is_zero(llvm::Value* const value)
{
    if (auto constant = llvm::dyn_cast<llvm::ConstantInt>(value))
        return constant->isZero();
    return false;
}


llvm::Instruction* llvm_constant_expr_to_instruction(llvm::ConstantExpr* const expression, llvm::Instruction* const succ_instruction)
{
    switch (expression->getOpcode())
    {
    case llvm::Instruction::Add:
    case llvm::Instruction::Sub:
    case llvm::Instruction::Mul:
    case llvm::Instruction::UDiv:
    case llvm::Instruction::SDiv:
    case llvm::Instruction::FDiv:
    case llvm::Instruction::URem:
    case llvm::Instruction::SRem:
    case llvm::Instruction::FRem:
    case llvm::Instruction::Shl:
    case llvm::Instruction::LShr:
    case llvm::Instruction::AShr:
    case llvm::Instruction::And:
    case llvm::Instruction::Or:
    case llvm::Instruction::Xor:
        return llvm::BinaryOperator::Create(
                    static_cast<llvm::Instruction::BinaryOps>(expression->getOpcode()),
                    expression->getOperand(0),
                    expression->getOperand(1),
                    expression->getName(),
                    succ_instruction);

    case llvm::Instruction::Trunc:
    case llvm::Instruction::ZExt:
    case llvm::Instruction::SExt:
    case llvm::Instruction::FPToUI:
    case llvm::Instruction::FPToSI:
    case llvm::Instruction::UIToFP:
    case llvm::Instruction::SIToFP:
    case llvm::Instruction::FPTrunc:
    case llvm::Instruction::FPExt:
    case llvm::Instruction::PtrToInt:
    case llvm::Instruction::IntToPtr:
    case llvm::Instruction::BitCast:
        return ::llvm::CastInst::Create(
                    static_cast<llvm::Instruction::CastOps>(expression->getOpcode()),
                    expression->getOperand(0),
                    expression->getType(),
                    expression->getName(),
                    succ_instruction);

    case llvm::Instruction::GetElementPtr:
        {
            std::vector<llvm::Value*> idxs;
            bool has_non_zero_index = false;
            for (unsigned int i = 1; i < expression->getNumOperands(); ++i)
            {
                idxs.push_back(expression->getOperand(i));
                if (!llvm_is_zero(idxs.back()))
                    has_non_zero_index = true;
            }
            if (!has_non_zero_index)
                return llvm::BitCastInst::CreatePointerCast(
                            expression->getOperand(0),
                            expression->getType(),
                            expression->getName(),
                            succ_instruction);

            auto pointee_type = expression->getType();
            auto ptr = expression->getOperand(0);                            
            return llvm::GetElementPtrInst::Create(
                        llvm::cast<llvm::PointerType>(ptr->getType()->getScalarType())->isOpaqueOrPointeeTypeMatches(pointee_type) ?
                            pointee_type : llvm::cast<llvm::PointerType>(ptr->getType()->getScalarType())->getPointerElementType(),
                        ptr,
                        llvm::makeArrayRef(idxs),
                        expression->getName(),
                        succ_instruction);
        }

    case llvm::Instruction::ICmp:
        {

            return ::llvm::ICmpInst::Create(
                        static_cast<llvm::Instruction::OtherOps>(expression->getOpcode()),
                        (llvm::CmpInst::Predicate)expression->getPredicate(),
                        expression->getOperand(0),
                        expression->getOperand(1),
                        expression->getName(),
                        succ_instruction);
        }

    case llvm::Instruction::Select:
    case llvm::Instruction::ExtractElement:
    case llvm::Instruction::InsertElement:
        std::cout << "NOT_IMPLEMENTED_YET: " << llvm_to_str(expression) << std::endl;
        NOT_IMPLEMENTED_YET();

    default:
        std::cout << "NOT_IMPLEMENTED_YET: " << llvm_to_str(expression) << std::endl;
        throw std::runtime_error("An unsupported constant expression reachaed.");
    }
}


bool llvm_basic_block_contains_intrinsic_before_instruction(
    llvm::BasicBlock const* llvm_block,
    llvm::Intrinsic::ID llvm_intrinsic_id,
    llvm::Instruction const* llvm_instruction
    )
{
    for (auto it = llvm_block->begin(); it != llvm_block->end(); ++it)
        if (&*it == llvm_instruction)
            return false;
        else
        {
            llvm::IntrinsicInst const* const intrinsic_instr = llvm::dyn_cast<llvm::IntrinsicInst>(&*it);
            if (intrinsic_instr != nullptr && intrinsic_instr->getIntrinsicID() == llvm_intrinsic_id)
                return true;
        }
    return false;
}


bool llvm_basic_block_contains_intrinsic(llvm::BasicBlock const* const llvm_block, llvm::Intrinsic::ID const llvm_intrinsic_id)
{
    for (auto it = llvm_block->begin(); it != llvm_block->end(); ++it)
    {
        llvm::IntrinsicInst const* const intrinsic_instr = llvm::dyn_cast<llvm::IntrinsicInst>(&*it);
        if (intrinsic_instr != nullptr && intrinsic_instr->getIntrinsicID() == llvm_intrinsic_id)
            return true;
    }
    return false;
}


bool llvm_function_contains_intrinsic(llvm::Function const* const llvm_function, llvm::Intrinsic::ID const llvm_intrinsic_id)
{
    for (auto it = llvm_function->begin(); it != llvm_function->end(); ++it)
        if (llvm_basic_block_contains_intrinsic(&*it, llvm_intrinsic_id))
            return true;
    return false;
}
