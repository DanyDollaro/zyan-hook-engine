/***************************************************************************************************

  Zyan Hook Library (Zyrex)

  Original Author : Florian Bernd

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

#include <Zycore/LibC.h>
#include <Zycore/Status.h>
#include <Zycore/Types.h>
#include <Zycore/Vector.h>
#include <Zydis/Zydis.h>
#include <Zyrex/Internal/Analysis.h>
#include <Zyrex/Internal/Relocation.h>

/* ============================================================================================== */
/* Internal functions                                                                             */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Relocation analysis functions                                                                  */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Checks if the given relative branch instruction needs to be rewritten in order to
 *          reach the destination address.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      check.
 *
 * @return  `ZYAN_TRUE` if the given relative branch instruction needs to be rewritten in order to
 *          reach the destination address or `ZYAN_FALSE`, if not.
 */
static ZyanBool ZyrexShouldRewriteBranchInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* instruction)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(instruction);
    ZYAN_ASSERT(instruction->has_relative_target);
    ZYAN_ASSERT(instruction->has_external_target);

    const ZyanU64 source_address = (ZyanU64)context->destination + context->bytes_written;

    switch (instruction->instruction.raw.imm[0].size)
    {
    case 8:
    {
        const ZyanI64 distance = (ZyanI64)(instruction->absolute_target_address - source_address - 
            instruction->instruction.length);
        if ((distance < ZYAN_INT8_MIN) || (distance > ZYAN_INT8_MAX))
        {
            return ZYAN_TRUE;
        }
        break;
    }
    case 16:
    {
        const ZyanI64 distance = (ZyanI64)(instruction->absolute_target_address - source_address -
            instruction->instruction.length);
        if ((distance < ZYAN_INT16_MIN) || (distance > ZYAN_INT16_MAX))
        {
            return ZYAN_TRUE;
        }
        break;
    }
    case 32:
    {
        const ZyanI64 distance = (ZyanI64)(instruction->absolute_target_address - source_address -
            instruction->instruction.length);
        if ((distance < ZYAN_INT32_MIN) || (distance > ZYAN_INT32_MAX))
        {
            return ZYAN_TRUE;
        }
        break;
    }
    default:
        ZYAN_UNREACHABLE;
    }

    return ZYAN_FALSE;
}

/**
 * @brief   Checks if the given relative memory instruction should be redirected to not access
 *          any memory inside the relocated code chunk.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      check.
 *
 * @return  `ZYAN_STATUS_TRUE` if the given memory instruction should be redirected to not access
 *          any memory inside the relocated code chunk or `ZYAN_STATUS_FALSE`, if not.
 *
 * The instruction should be redirected, if it would access any memory inside the relocated code
 * chunk. This prevents wrong data being read due to modifications of the instructions during the
 * relocation process.
 */
//static ZyanStatus ZyrexShouldRedirectMemoryInstruction(ZyrexRelocationContext* context,
//    const ZyrexAnalyzedInstruction* instruction)
//{
//    ZYAN_ASSERT(context);
//    ZYAN_ASSERT(instruction);
//    ZYAN_ASSERT(instruction->has_relative_target);
//
//    return !instruction->has_external_target;
//}

/* ---------------------------------------------------------------------------------------------- */
/* Relocation                                                                                     */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Relocates a single common instruction (without a relative offset) and updates the
 *          relocation-context.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      relocate.
 *
 * @return  A zyan status code.
 */
static ZyanStatus ZyrexRelocateCommonInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* instruction)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(instruction);

    // Relocate instruction
    ZYAN_MEMCPY((ZyanU8*)context->destination + context->bytes_written,
        (const ZyanU8*)context->source + context->bytes_read, instruction->instruction.length);

    // Update relocation context
    ZyrexUpdateTranslationContext(context, instruction->instruction.length,
        (ZyanU8)context->bytes_read, (ZyanU8)context->bytes_written);

    return ZYAN_STATUS_SUCCESS;
}

/**
 * @brief   Relocates the given relative branch instruction and updates the relocation-context.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      relocate.
 *
 * @return  A zyan status code.
 */
static ZyanStatus ZyrexRelocateRelativeBranchInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* instruction)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(instruction);

    if (!instruction->has_external_target)
    {
        // Offsets for relative instructions with internal target addresses are fixed up later by
        // the `ZyrexUpdateInstructionOffsets` function ...
        return ZyrexRelocateCommonInstruction(context, instruction);
    }

    if (ZyrexShouldRewriteBranchInstruction(context, instruction))
    {
        // Rewrite branch instructions for which no alternative form with 32-bit offset exists
        switch (instruction->instruction.mnemonic)
        {
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
        {
            // E.g. the following code:
            /*
             * @__START:
             *   ...
             *   JECXZ @__TARGET
             *   ...
             *   ...
             * @__TARGET:
             *   ...
             */

            // ... will be transformed to:
            /*
             * @__START:
             *   ...
             *   JECXZ @__CASE1
             *   JMP SHORT @__CASE0
             * @__CASE1:
             *   JMP @__TARGET
             * @__CASE0:
             *   ...
             *   ...
             * @__TARGET: (external)
             *   ...
             */

            ZyanU8* address = (ZyanU8*)context->destination + context->bytes_written;

            // Copy original instruction and modify relative offset
            ZYAN_MEMCPY(address, (const ZyanU8*)context->source + context->bytes_read,
                instruction->instruction.length);
            *(address + instruction->instruction.raw.imm[0].offset) = 0x02;
            address += instruction->instruction.length;

            ZyrexUpdateTranslationContext(context, instruction->instruction.length,
                (ZyanU8)context->bytes_read, (ZyanU8)context->bytes_written);

            // Generate `JMP` to `0` branch
            *address++ = 0xEB;
            *address++ = 0x05;
            ZyrexUpdateTranslationContext(context, 2, (ZyanU8)context->bytes_read,
                (ZyanU8)context->bytes_written + instruction->instruction.length);

            // Generate `JMP` to `1` branch
            ZyrexWriteRelativeJump(address, (ZyanUPointer)instruction->absolute_target_address);
            ZyrexUpdateTranslationContext(context, 5, (ZyanU8)context->bytes_read,
                (ZyanU8)context->bytes_written + instruction->instruction.length + 2);

            return ZYAN_STATUS_SUCCESS;
        }
        default:
            break;
        }

        // Enlarge branch instructions for which an alternative form with 32-bit offset exists
        ZyanU8 opcode;
        ZyanU8 length = 6;
        switch (instruction->instruction.mnemonic)
        {
        case ZYDIS_MNEMONIC_JMP:
        {
            opcode = 0xE9;
            length = 5;
            break;
        }
        case ZYDIS_MNEMONIC_JO  : opcode = 0x80; break;
        case ZYDIS_MNEMONIC_JNO : opcode = 0x81; break;
        case ZYDIS_MNEMONIC_JB  : opcode = 0x82; break;
        case ZYDIS_MNEMONIC_JNB : opcode = 0x83; break;
        case ZYDIS_MNEMONIC_JZ  : opcode = 0x84; break;
        case ZYDIS_MNEMONIC_JNZ : opcode = 0x85; break;
        case ZYDIS_MNEMONIC_JBE : opcode = 0x86; break;
        case ZYDIS_MNEMONIC_JNBE: opcode = 0x87; break;
        case ZYDIS_MNEMONIC_JS  : opcode = 0x88; break;
        case ZYDIS_MNEMONIC_JNS : opcode = 0x89; break;
        case ZYDIS_MNEMONIC_JP  : opcode = 0x8A; break;
        case ZYDIS_MNEMONIC_JNP : opcode = 0x8B; break;
        case ZYDIS_MNEMONIC_JL  : opcode = 0x8C; break;
        case ZYDIS_MNEMONIC_JNL : opcode = 0x8D; break;
        case ZYDIS_MNEMONIC_JLE : opcode = 0x8E; break;
        case ZYDIS_MNEMONIC_JNLE: opcode = 0x8F; break;
        default:
            ZYAN_UNREACHABLE;
        }

        // Write opcode
        ZyanU8* address = (ZyanU8*)context->destination + context->bytes_written;        
        if (opcode == 0xE9)
        {
            *address++ = 0xE9;
        } else
        {
            *address++ = 0x0F;
            *address++ = opcode;
        }

        // Write relative offset
        *(ZyanI32*)(address) = 
            ZyrexCalculateRelativeOffset(4, (ZyanUPointer)address, 
                (ZyanUPointer)instruction->absolute_target_address);

        // Update relocation context
        ZyrexUpdateTranslationContext(context, length, (ZyanU8)context->bytes_read, 
            (ZyanU8)context->bytes_written);

        return ZYAN_STATUS_SUCCESS;
    }

    void* const offset_address = (ZyanU8*)context->destination + context->bytes_written +
        instruction->instruction.raw.imm[0].offset;

    // First copy the instruction like it is ...
    ZYAN_CHECK(ZyrexRelocateCommonInstruction(context, instruction));

    // Update the relative offset for the new instruction position
    const ZyanI32 value = ZyrexCalculateRelativeOffset(0,
        (ZyanUPointer)context->destination + context->bytes_written,
        (ZyanUPointer)instruction->absolute_target_address);

    switch (instruction->instruction.raw.imm[0].size)
    {
    case  8: *((ZyanI8* )offset_address) = (ZyanI8 )value; break;
    case 16: *((ZyanI16*)offset_address) = (ZyanI16)value; break;
    case 32: *((ZyanI32*)offset_address) = (ZyanI32)value; break;
    default:
        ZYAN_UNREACHABLE;
    }

    return ZYAN_STATUS_SUCCESS;
}

/**
 * @brief   Relocates the given instruction with relative memory operand and updates the
 *          relocation-context.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      relocate.
 *
 * @return  A zyan status code.
 */
static ZyanStatus ZyrexRelocateRelativeMemoryInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* instruction)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(instruction);

    // We have to update the offset of relative memory instructions with targets outside the
    // relocated code chunk
    if (instruction->has_external_target)
    {
        void* const offset_address = (ZyanU8*)context->destination + context->bytes_written +
            instruction->instruction.raw.disp.offset;

        // First copy the instruction like it is ...
        ZYAN_CHECK(ZyrexRelocateCommonInstruction(context, instruction));

        // Update the relative offset for the new instruction position
        const ZyanI32 value = ZyrexCalculateRelativeOffset(0, 
            (ZyanUPointer)context->destination + context->bytes_written, 
            (ZyanUPointer)instruction->absolute_target_address);

        switch (instruction->instruction.raw.disp.size)
        {
        case  8: *((ZyanI8* )offset_address) = (ZyanI8 )value; break;
        case 16: *((ZyanI16*)offset_address) = (ZyanI16)value; break;
        case 32: *((ZyanI32*)offset_address) = (ZyanI32)value; break;
        default:
            ZYAN_UNREACHABLE;
        }

        return ZYAN_STATUS_SUCCESS;
    }

    return ZyrexRelocateCommonInstruction(context, instruction);   
}

/**
 * @brief   Relocates a single relative instruction and updates the relocation-context.
 *
 * This function takes care of code rewriting and/or enlarging the instruction to 32-bit if needed.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      relocate.
 *
 * @return  A zyan status code.
 */
static ZyanStatus ZyrexRelocateRelativeInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* instruction)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(instruction);

    // Relocate relative branch instruction
    if (ZyrexIsRelativeBranchInstruction(&instruction->instruction))
    {
        return ZyrexRelocateRelativeBranchInstruction(context, instruction);
    }

    // Relocate instruction with relative memory operand
    if (ZyrexIsRelativeMemoryInstruction(&instruction->instruction))
    {
        return ZyrexRelocateRelativeMemoryInstruction(context, instruction);
    }

    // We should not be able to reach this code, if we correctly handled all existing relative
    // instructions   
    ZYAN_UNREACHABLE;
}

/**
 * @brief   Takes the offset of an instruction in the source buffer and returns the offset of the
 *          same instruction in the destination buffer.
 *
 * @param   context             A pointer to the `ZyrexRelocationContext` struct.
 * @param   offset_source       The offset of the instruction in the source buffer.
 * @param   offset_destination  Receives the offset of the instruction in the destination buffer.
 *
 * If the source instruction has been rewritten into a code-block of multiple instructions, the
 * offset of the first instruction is returned.
 *
 * @return  A zyan status code.
 */
static ZyanStatus ZyrexGetRelocatedInstructionOffset(ZyrexTranslationContext* context, 
    ZyanU8 offset_source, ZyanU8* offset_destination)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(offset_destination);
    ZYAN_ASSERT(context->instructions.size <= context->translation_map->count);

    for (ZyanUSize i = 0; i < context->translation_map->count; ++i)
    {
        const ZyrexInstructionTranslationItem* item = &context->translation_map->items[i];
        if (item->offset_source == offset_source)
        {
            *offset_destination = item->offset_destination;
            return ZYAN_STATUS_SUCCESS;
        }
    }

    return ZYAN_STATUS_NOT_FOUND;
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Functions                                                                                      */
/* ============================================================================================== */

ZyanStatus ZyrexUpdateInstructionsOffsets(ZyrexTranslationContext* context)
{
    ZYAN_ASSERT(context);

    for (ZyanUSize i = 0; i < context->instructions.size; ++i)
    {
        const ZyrexAnalyzedInstruction* const instruction = 
            ZyanVectorGet(&context->instructions, i);

        if (!instruction->has_relative_target || instruction->has_external_target)
        {
            // The instruction does not have a relative target or the relative offset is pointing
            // to an address outside of the destination buffer
            continue;
        }

        // TODO: Handle RIP-rel memory operand accessing memory of rewritten instructions
        // TODO: e.g. by redirecting access to the original data saved in the trampoline chunk
        // TODO: Do the same thing for (32-bit) instructions with absolute memory operand
        // TODO: (both situations should be really rare edge cases)

        ZyanU8 offset = 0;
        ZyanU8 size   = 0;
        if (ZyrexIsRelativeBranchInstruction(&instruction->instruction))
        {
            offset = instruction->instruction.raw.imm[0].offset;
            size   = instruction->instruction.raw.imm[0].size;
        }
        if (ZyrexIsRelativeMemoryInstruction(&instruction->instruction))
        {
            offset = instruction->instruction.raw.disp.offset;
            size   = instruction->instruction.raw.disp.size;
        }
        ZYAN_ASSERT(size > 0);

        // Lookup the offset of the instruction in the destination buffer
        ZyanU8 offset_instruction;
        ZYAN_CHECK(ZyrexGetRelocatedInstructionOffset(context, (ZyanU8)instruction->address_offset, 
            &offset_instruction));

        // Lookup the offset of the destination instruction in the destination buffer
        const ZyrexAnalyzedInstruction* const destination =
            ZyanVectorGet(&context->instructions, instruction->outgoing);
        ZYAN_ASSERT(destination);
        ZyanU8 offset_destination;
        ZYAN_CHECK(ZyrexGetRelocatedInstructionOffset(context, (ZyanU8)destination->address_offset, 
            &offset_destination));

        void* const address_of_offset = (ZyanU8*)context->destination + offset_instruction + offset;
        const ZyanI32 value = ZyrexCalculateRelativeOffset(instruction->instruction.length, 
            offset_instruction, offset_destination);

        switch (size)
        {
        case  8: *((ZyanI8* )address_of_offset) = (ZyanI8 )value; break;
        case 16: *((ZyanI16*)address_of_offset) = (ZyanI16)value; break;
        case 32: *((ZyanI32*)address_of_offset) = (ZyanI32)value; break;
        default:
            ZYAN_UNREACHABLE;
        }
    }

    return ZYAN_STATUS_SUCCESS;
}

ZyanStatus ZyrexRelocateInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* const instruction)
{
    ZYAN_ASSERT(context);
    ZYAN_ASSERT(instruction);

    ZYAN_CHECK(instruction->has_relative_target
        ? ZyrexRelocateRelativeInstruction(context, instruction)
        : ZyrexRelocateCommonInstruction(context, instruction)
    );

    context->bytes_read += instruction->instruction.length;
    ++context->instructions_read;

    return ZYAN_STATUS_SUCCESS;
}

/* ============================================================================================== */
