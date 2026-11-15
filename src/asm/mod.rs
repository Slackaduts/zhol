use crate::hooks::*;

use dynasmrt::{dynasm, x86::X86Relocation, Assembler, DynasmApi};

/// Compiles a dynasmrt Assembler, and propagates errors as MemOpError.
///
/// # Arguments
/// * `ops`: X86 Assembler object, after dynasm! has been called
/// # Returns
/// * `crate::MemOpResult<Vec<usize>>`: Anyhow result containing the bytes of compiled x86 ASM
pub fn handle_x86_asm_build(ops: Assembler<X86Relocation>) -> crate::MemOpResult<Vec<u8>> {
    return match ops.finalize() {
        Err(e) => Err(crate::memop_err!(
            "Error occured when compiling bytecode: \"{:#?}\"",
            e
        )),
        Ok(b) => Ok(b.to_vec()),
    };
}

/// Calculates the relative instruction offset between two addresses.
///
/// # Arguments
/// * `ops`: Assembler object containing the current offset
/// * `origin`: The address of the instruction that will be jumped from
/// * `dest`: The address of the instruction that will be jumped to
/// * `inst_size`: The size of the instruction that will be jumped from
/// # Returns
/// * `i32`: The relative offset between the two addresses
pub fn calc_rel_inst(
    ops: &Assembler<X86Relocation>,
    origin: usize,
    dest: usize,
    inst_size: usize,
) -> i32 {
    (dest as i32) - (origin as i32 + (ops.offset().0 as i32 - 1) + inst_size as i32)
}

/// Fills a given remaining space of an assembly instruction builder with nops.
fn apply_nops(
    ops: &mut Assembler<X86Relocation>,
    iterations: usize,
) -> &mut Assembler<X86Relocation> {
    for _ in 1..iterations {
        dynasm!(ops
            ; nop
        );
    }

    ops
}

// /// Appends a relative jump instruction to the end of the Assembler object.
// ///
// /// # Arguments
// /// * `ops`: Assembler object to append the jump instruction to
// /// * `hook`: Hook object containing the hook memory address
// /// * `target`: The address to jump to
// /// # Returns
// /// * `crate::MemOpResult<()>`: Anyhow result indicating success or failure
// pub fn end_jmp<T: HookImpl>(
//     ops: &mut Assembler<X86Relocation>,
//     nops: Option<usize>,
//     hook: &Hook<T>,
//     target: usize,
// ) -> crate::MemOpResult<()> {
//     let rel_return = calc_rel_inst(
//         &ops,
//         hook.hook_mem.addr as usize,
//         target,
//         hook.get_jmp_size()?,
//     );
//     dynasm!(ops
//         ; jmp rel_return
//     );

//     if let Some(n) = nops {
//         apply_nops(ops, n);
//     }

//     Ok(())
// }

// /// Sets up a `dynasm::Assembler` to a hook's newmem address.
// ///
// /// # Arguments
// /// * `hook`: Hook object containing the hook memory address
// /// # Returns
// /// * `crate::MemOpResult<dynasm::Assembler<dynasmrt::x86::X86Relocation>>`: Anyhow result containing the Assembler object
// pub fn newmem_jmp<T: HookImpl>(hook: &Hook<T>) -> crate::MemOpResult<Assembler<X86Relocation>> {
//     let mut ops: Assembler<X86Relocation> = Assembler::new()?;
//     let newmem = hook.hook_mem.addr as i32;
//     let newmem_rel_jmp = newmem - (hook.get_addr()? as i32 + 5);

//     dynasm!(ops
//         ; .arch x86
//         ; jmp newmem_rel_jmp
//     );

//     Ok(ops)
// }

/// Sets up a `dynasm::Assembler` to a hook's newmem address.
///
/// # Arguments
/// * `hook`: Hook runtime data
/// # Returns
/// * `crate::MemOpResult<dynasm::Assembler<dynasmrt::x86::X86Relocation>>`: Anyhow result containing the Assembler object
pub fn newmem_jmp(hook: &HookData) -> crate::MemOpResult<Assembler<X86Relocation>> {
    let mut ops: Assembler<X86Relocation> = Assembler::new()?;
    let newmem = hook.hook_mem.addr as i32;
    let newmem_rel_jmp = newmem - (hook.get_addr()? as i32 + 5);

    dynasm!(ops
        ; .arch x86
        ; jmp newmem_rel_jmp
    );

    Ok(ops)
}

/// Appends a relative jump instruction to the end of the Assembler object.
///
/// # Arguments
/// * `ops`: Assembler object to append the jump instruction to
/// * `hook_data`: Hook runtime data
/// * 'hook_impl': Hook impl to use, supplies hook-specific compiletime data
/// * `target`: The address to jump to
/// # Returns
/// * `crate::MemOpResult<()>`: Anyhow result indicating success or failure
pub fn end_jmp(
    ops: &mut Assembler<X86Relocation>,
    nops: Option<usize>,
    hook_data: &HookData,
    hook_impl: &dyn HookImpl,
    target: usize,
) -> crate::MemOpResult<()> {
    let rel_return = calc_rel_inst(
        &ops,
        hook_data.hook_mem.addr as usize,
        target,
        hook_data.get_jmp_size(hook_impl)?,
    );
    dynasm!(ops
        ; jmp rel_return
    );

    if let Some(n) = nops {
        apply_nops(ops, n);
    }

    Ok(())
}
