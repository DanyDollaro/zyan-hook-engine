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

#ifndef ZYREX_INTERNAL_RELOCATION_H
#define ZYREX_INTERNAL_RELOCATION_H

#include <Zycore/Types.h>
#include <Zyrex/Internal/Trampoline.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================================== */
/* Functions                                                                                      */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/*                                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Updates the offsets of instructions with relative offsets pointing to instructions
 *          inside the relocated code.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 *
 * @return  A zyan status code.
 *
 * As some of the instructions might have been enlarged or rewritten, there is a chance that the
 * relative offset of previous instructions does not point to the correct target any longer. This
 * function compensates all instruction shifts happened during the relocation process.
 */
ZyanStatus ZyrexUpdateInstructionsOffsets(ZyrexTranslationContext* context);

/**
 * @brief   Relocates a single instruction and updates the relocation-context.
 *
 * @param   context     A pointer to the `ZyrexRelocationContext` struct.
 * @param   instruction A pointer to the `ZyrexAnalyzedInstruction` struct of the instruction to
 *                      relocate.
 *
 * @return  A zyan status code.
 */
ZyanStatus ZyrexRelocateInstruction(ZyrexTranslationContext* context,
    const ZyrexAnalyzedInstruction* const instruction);

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* ZYREX_INTERNAL_RELOCATION_H */
