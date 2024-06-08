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

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Analyzed instruction                                                                           */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Defines the `ZyrexAnalyzedInstruction` struct.
 */
typedef struct ZyrexAnalyzedInstruction_
{
    /**
     * @brief   The address of the instruction relative to the start of the source buffer.
     */
    ZyanUSize address_offset;
    /**
     * @brief   The absolute runtime/memory address of the instruction.
     */
    ZyanUPointer address;
    /**
     * @brief   The `ZydisDecodedInstruction` struct of the analyzed instruction.
     */
    ZydisDecodedInstruction instruction;
    /**
     * @brief   Signals, if the instruction refers to a target address using a relative offset.
     */
    ZyanBool has_relative_target;
    /**
     * @brief   Signals, if the target address referred by the relative offset is not inside the
     *          analyzed code chunk.
     */
    ZyanBool has_external_target;
    /**
     * @brief   Signals, if this instruction is targeted by at least one instruction from inside
     *          the analyzed code chunk.
     */
    ZyanBool is_internal_target;
    /**
     * @brief   The absolute target address of the instruction calculated from the relative offset,
     *          if applicable.
     */
    ZyanU64 absolute_target_address;
    /**
     * @brief   Contains the ids of all instructions inside the analyzed code chunk that are
     *          targeting this instruction using a relative offset.
     */
    ZyanVector/*<ZyanU8>*/ incoming;
    /**
     * @brief   The id of an instruction inside the analyzed code chunk which is targeted by
     *          this instruction using a relative offset, or `-1` if not applicable.
     */
    ZyanU8 outgoing;
} ZyrexAnalyzedInstruction;

/* ---------------------------------------------------------------------------------------------- */

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
static void ZyrexAnalyzedInstructionDestroy(ZyrexAnalyzedInstruction* item)
{
    ZYAN_ASSERT(item);

    if (item->is_internal_target)
    {
        ZyanVectorDestroy(&item->incoming);
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* Instruction analysis                                                                           */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Analyzes the code in the source buffer and updates the relocation-context.
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
    ZyanUSize capacity, ZyanUSize* bytes_read);

/**
 * @brief   Checks if the given instruction is a relative branch instruction.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct of the instruction to
 *                      check.
 *
 * @return  `ZYAN_TRUE` if the instruction is a supported relative branch instruction or
 *          `ZYAN_FALSE`, if not.
 */
ZyanBool ZyrexIsRelativeBranchInstruction(const ZydisDecodedInstruction* instruction);

/**
 * @brief   Checks if the given instruction is an instruction with a relative memory operand.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct of the instruction to
 *                      check.
 *
 * @return  `ZYAN_TRUE` if the instruction is an instruction with a relative memory operand or
 *          `ZYAN_FALSE`, if not.
 */
ZyanBool ZyrexIsRelativeMemoryInstruction(const ZydisDecodedInstruction* instruction);

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
