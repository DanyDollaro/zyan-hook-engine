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

#include <Zydis/Zydis.h>
#include <Zyrex/Internal/Utils.h>
#include <Zyrex/Internal/Analysis.h>

/* ============================================================================================== */
/* Functions                                                                                      */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* ZyrexAnalyzedInstruction                                                                       */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Finalizes the given `ZyrexAnalyzedInstruction` struct.
 *
 * @param   item    A pointer to the `ZyrexAnalyzedInstruction` struct.
 */
static void ZyrexAnalyzedInstructionDestroy(ZyrexAnalyzedInstruction* item);

/* ---------------------------------------------------------------------------------------------- */
/* Instruction analysis                                                                           */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Analyzes the code in the source buffer.
 *
 * @param   buffer              A pointer to the buffer that contains the code to analyze.
 * @param   length              The length of the buffer.
 * @param   bytes_to_analyze    The minimum number of bytes to analyze. More bytes might get
 *                              accessed on demand to keep individual instructions intact.
 * @param   instructions        Returns a new `ZyanVector` instance which contains all analyzed
 *                              instructions.
 *                              The vector needs to manually get destroyed by calling
 *                              `ZyanVectorDestroy` when no longer needed.
 * @param   bytes_read          Returns the exact amount of bytes read from the buffer.
 *
 * @return  A zyan status code.
 */
ZyanStatus ZyrexAnalyzeInstructions(const void* buffer, ZyanUSize length,
    ZyanUSize bytes_to_analyze, ZyanVector/*<ZyrexAnalyzedInstruction>*/* instructions,
    ZyanUSize capacity, ZyanUSize* bytes_read)
{
    ZYAN_ASSERT(buffer);
    ZYAN_ASSERT(length);
    ZYAN_ASSERT(bytes_to_analyze);

    ZydisDecoder decoder;
#if defined(ZYAN_X86)
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#elif defined(ZYAN_X64)
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
#   error "Unsupported architecture detected"
#endif

    ZYAN_CHECK(ZyanVectorInit(instructions, sizeof(ZyrexAnalyzedInstruction),
        capacity, (ZyanMemberProcedure)&ZyrexAnalyzedInstructionDestroy));

    // First pass:
    //   - Determine exact amount of instructions and instruction bytes
    //   - Decode all instructions and calculate relative target address for instructions with
    //     relative offsets
    //
    ZyanUSize offset = 0;
    while (offset < bytes_to_analyze)
    {
        ZyrexAnalyzedInstruction item;

        ZYAN_CHECK(ZydisDecoderDecodeInstruction(&decoder, ZYAN_NULL,
            (const ZyanU8*)buffer + offset, length - offset, &item.instruction));

        item.address_offset = offset;
        item.address = (ZyanUPointer)(const ZyanU8*)buffer + offset;
        item.has_relative_target = (item.instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
            ? ZYAN_TRUE
            : ZYAN_FALSE;
        item.has_external_target = item.has_relative_target;
        item.absolute_target_address = 0;
        if (item.has_relative_target)
        {
            ZYAN_CHECK(ZyrexCalcAbsoluteAddress(&item.instruction,
                (ZyanU64)buffer + offset, &item.absolute_target_address));
        }
        item.is_internal_target = ZYAN_FALSE;
        item.outgoing = (ZyanU8)(-1);
        ZYAN_CHECK(ZyanVectorPushBack(instructions, &item));

        offset += item.instruction.length;
    }

    ZYAN_ASSERT(offset >= bytes_to_analyze);
    *bytes_read = offset;

    // Second pass:
    //   - Find internal outgoing target for instructions with relative offsets
    //   - Find internal incoming targets from instructions with relative offsets
    //
    for (ZyanUSize i = 0; i < instructions->size; ++i)
    {
        ZyrexAnalyzedInstruction* const current = ZyanVectorGetMutable(instructions, i);
        ZYAN_ASSERT(current);

        for (ZyanUSize j = 0; j < instructions->size; ++j)
        {
            ZyrexAnalyzedInstruction* const item = ZyanVectorGetMutable(instructions, j);
            ZYAN_ASSERT(item);

            if (item->has_relative_target && (item->absolute_target_address == current->address))
            {
                // The `item` instruction targets the `current` instruction
                item->has_external_target = ZYAN_FALSE;
                item->outgoing = (ZyanU8)i;

                // The `current` instruction is an internal target of the `item` instruction
                if (!current->is_internal_target)
                {
                    current->is_internal_target = ZYAN_TRUE;
                    ZYAN_CHECK(ZyanVectorInit(&current->incoming, sizeof(ZyanU8), 2,
                        ZYAN_NULL));
                }
                const ZyanU8 value = (ZyanU8)j;
                ZYAN_CHECK(ZyanVectorPushBack(&current->incoming, &value));
            }
        }
    }

    return ZYAN_STATUS_SUCCESS;
}

/**
 * @brief   Checks if the given instruction is a relative branch instruction.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct of the instruction to
 *                      check.
 *
 * @return  `ZYAN_TRUE` if the instruction is a supported relative branch instruction or
 *          `ZYAN_FALSE`, if not.
 */
ZyanBool ZyrexIsRelativeBranchInstruction(const ZydisDecodedInstruction* instruction)
{
    ZYAN_ASSERT(instruction);

    if (!instruction->raw.imm[0].is_relative)
    {
        return ZYAN_FALSE;
    }

    switch (instruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        return ZYAN_TRUE;
    default:
        return ZYAN_FALSE;
    }
}

/**
 * @brief   Checks if the given instruction is an instruction with a relative memory operand.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct of the instruction to
 *                      check.
 *
 * @return  `ZYAN_TRUE` if the instruction is an instruction with a relative memory operand or
 *          `ZYAN_FALSE`, if not.
 */
ZyanBool ZyrexIsRelativeMemoryInstruction(const ZydisDecodedInstruction* instruction)
{
    ZYAN_ASSERT(instruction);

    return ((instruction->attributes & ZYDIS_ATTRIB_HAS_MODRM) &&
        (instruction->raw.modrm.mod == 0) && (instruction->raw.modrm.rm == 5))
        ? ZYAN_TRUE
        : ZYAN_FALSE;
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
