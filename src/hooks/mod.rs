#[cfg(feature = "async")]
pub mod async_ext;

use crate::memory::{MemOpContext, MemoryRegion};
use crate::process::SafeHandle;

use anyhow::{anyhow, Result};
use std::time::Duration;

#[cfg(feature = "aob-injection")]
use crate::asm::{handle_x86_asm_build, newmem_jmp};
#[cfg(feature = "aob-injection")]
use crate::memory::utils::allocate_memory;
#[cfg(feature = "aob-injection")]
use crate::memory::{
    read::read_bytes, utils::change_memory_protection, write::write_bytes, Byte,
};
#[cfg(feature = "aob-injection")]
use crate::process::module::{get_module_info, module_by_name};
#[cfg(feature = "aob-injection")]
use crate::process::pattern::{create_unhook_bytes, find_pattern_in_bytes};
#[cfg(feature = "aob-injection")]
use windows::Win32::System::{Memory::PAGE_READWRITE, ProcessStatus::MODULEINFO};

pub type ZholHook = std::sync::Arc<dyn HookOps>;

/// Base trait for all exploit implementations.
/// 
/// This trait provides a generic interface that all exploit types must implement,
/// allowing for a unified hook management system regardless of the underlying exploit technique.
pub trait ExploitImpl: Send + Sync + CloneExploitImpl {
    /// Returns the type of exploit this implementation handles
    fn exploit_type(&self) -> ExploitType;
    
    /// Returns the target identifier (module name, process name, DLL path, etc.)
    fn target(&self) -> &str;
    
    /// Execute the exploit using the provided handle and data
    fn execute(&self, handle: &SafeHandle, data: &mut ExploitData) -> Result<()>;
    
    /// Clean up/remove the exploit
    fn cleanup(&self, handle: &SafeHandle, data: &ExploitData) -> Result<()>;
    
    /// Check if the exploit is currently active
    fn is_active(&self, data: &ExploitData) -> bool;
    
    /// Initialize exploit-specific data
    fn init_data(&self, handle: &SafeHandle) -> Result<ExploitData>;
}

/// Supported exploit types, gated behind feature flags
#[derive(Debug, Clone, PartialEq)]
pub enum ExploitType {
    #[cfg(feature = "aob-injection")]
    AobInjection,
    // Future exploit types would be added here:
    // #[cfg(feature = "dll-injection")]
    // DllInjection,
    // #[cfg(feature = "iat-hooking")]
    // IatHooking,
}

/// Exploit-specific runtime data
#[derive(Clone)]
pub enum ExploitData {
    #[cfg(feature = "aob-injection")]
    Aob(AobData),
    // Future exploit data types:
    // #[cfg(feature = "dll-injection")]
    // Dll(DllData),
}

/// Trait for cloning boxed ExploitImpl trait objects
pub trait CloneExploitImpl {
    fn clone_exploit_impl(&self) -> Box<dyn ExploitImpl>;
}

impl<T> CloneExploitImpl for T
where
    T: ExploitImpl + Clone + 'static,
{
    fn clone_exploit_impl(&self) -> Box<dyn ExploitImpl> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ExploitImpl> {
    fn clone(&self) -> Self {
        self.clone_exploit_impl()
    }
}

/// AOB (Array of Bytes) injection-specific implementation trait
#[cfg(feature = "aob-injection")]
pub trait AobExploitImpl: ExploitImpl {
    /// Returns the byte pattern to search for in the target module
    fn pattern(&self) -> &'static [Byte];
    
    /// Builds the hook bytecode to be injected
    fn build_hook(&self, data: &AobData) -> Result<Vec<u8>>;
    
    /// Builds the jump instruction to redirect execution to the hook
    fn build_jmp(&self, data: &AobData) -> Result<Vec<u8>> {
        let ops = newmem_jmp(data)?;
        handle_x86_asm_build(ops)
    }
    
    /// Size of variable memory allocation (default: 4 bytes)
    fn var_size(&self) -> usize {
        0x4
    }
    
    /// Size of hook memory allocation (default: 4KB)
    fn hook_alloc_size(&self) -> usize {
        0x1000
    }
    
    /// Target module name (default: "Zhol.exe")
    fn module_name(&self) -> &'static str {
        "Zhol.exe"
    }
}

/// Runtime data specific to AOB injection exploits
#[cfg(feature = "aob-injection")]
#[derive(Clone)]
pub struct AobData {
    pub module_addr: usize,
    pub hook_mem: MemoryRegion,
    pub var_mem: MemoryRegion,
    pub pattern: Vec<Byte>,
    pub var_size: usize,
    pub hook_alloc_size: usize,
    pub addr: Option<usize>,
    pub found_bytes: Option<Vec<u8>>,
}

#[cfg(feature = "aob-injection")]
impl AobData {
    pub fn get_addr(&self) -> Result<usize> {
        self.addr.ok_or(anyhow!(
            "get_addr() called without pattern scanned and injection point found."
        ))
    }

    pub fn get_jmp_size<T: AobExploitImpl + ?Sized>(&self, hook_impl: &T) -> Result<usize> {
        Ok(hook_impl.build_jmp(self)?.len())
    }

    pub fn get_nth_unhook_byte(&self, index: usize) -> Result<u8> {
        let found_bytes = self.found_bytes.as_ref().ok_or(anyhow!(
            "Unhook bytes called without pattern scanning and finding a match."
        ))?;

        found_bytes
            .get(index)
            .ok_or(anyhow!("Index \"{}\" not in range unhookbytes.", index))
            .copied()
    }
}

/// Copies clone implementation for exploits to be used with discrete process hooks.
#[macro_export]
macro_rules! impl_exploit_clone {
    ($type:ty) => {
        impl $type {
            fn clone_box_impl(&self) -> Box<dyn ExploitImpl> {
                Box::new(self.clone())
            }
        }

        impl CloneExploitImpl for $type {
            fn clone_exploit_impl(&self) -> Box<dyn ExploitImpl> {
                self.clone_box_impl()
            }
        }
    };
}


/// Top-level structure for a process hook.
/// 
/// Runtime data is separated from compile-time, which is separated from implementation.
#[derive(Clone)]
pub struct Hook {
    pub handle: SafeHandle,
    pub data: std::sync::Arc<parking_lot::RwLock<ExploitData>>,
    pub exploit_impl: Box<dyn ExploitImpl>,
}


#[cfg(feature = "aob-injection")]
impl Hook {
    pub fn new_aob(
        handle: SafeHandle,
        exploit_impl: impl AobExploitImpl + 'static,
    ) -> MemOpResult<std::sync::Arc<Self>> {
        // Initialize exploit data using the impl
        let data = exploit_impl.init_data(&handle)?;

        let hook_self = Self {
            handle,
            data: std::sync::Arc::new(parking_lot::RwLock::new(data)),
            exploit_impl: Box::new(exploit_impl),
        };

        Ok(std::sync::Arc::new(hook_self))
    }
    
    pub fn new(
        handle: SafeHandle,
        exploit_impl: impl AobExploitImpl + 'static,
    ) -> MemOpResult<std::sync::Arc<Self>> {
        Self::new_aob(handle, exploit_impl)
    }
}

unsafe impl Send for Hook {}
unsafe impl Sync for Hook {}

/// Hook-agnostic operations so the hook can be meaningfully interacted with in top-level logic.
/// 
/// Provides common functionality like hooking, unhooking, and inner specification retreival.
pub trait HookOps: Send + Sync {
    fn handle(&self) -> SafeHandle;
    fn data(&self) -> &std::sync::Arc<parking_lot::RwLock<ExploitData>>;
    fn exploit_impl(&self) -> &Box<dyn ExploitImpl>;

    fn hook(&self, timeout: Duration) -> MemOpResult<()>;
    fn unhook(&self, timeout: Duration) -> MemOpResult<()>;
    
    /// Creates MemOpContext for a default memory operation originating from the base of the hook
    /// Only available for AOB injection exploits
    #[cfg(feature = "aob-injection")]
    fn ctx(&self, offset: usize, at_pointer: bool, timeout: Option<Duration>) -> MemOpResult<MemOpContext> {
        let data = self.data().read();
        match &*data {
            ExploitData::Aob(aob_data) => {
                Ok(MemOpContext::new(aob_data.var_mem.addr, offset, at_pointer, timeout))
            }
        }
    }
}
use crate::MemOpResult;
impl HookOps for Hook {
    fn data(&self) -> &std::sync::Arc<parking_lot::RwLock<ExploitData>> {
        &self.data
    }

    fn handle(&self) -> SafeHandle {
        self.handle.clone()
    }

    fn exploit_impl(&self) -> &Box<dyn ExploitImpl> {
        &self.exploit_impl
    }

    fn hook(&self, _timeout: Duration) -> MemOpResult<()> {
        let mut data = self.data.write();
        self.exploit_impl.execute(&self.handle, &mut data)?;
        Ok(())
    }

    fn unhook(&self, _timeout: Duration) -> MemOpResult<()> {
        let data = self.data.read();
        self.exploit_impl.cleanup(&self.handle, &data)?;
        Ok(())
    }
}

/// Helper function to extract var_mem address from ExploitData for backward compatibility
#[cfg(feature = "aob-injection")]
pub fn get_var_mem_addr(data: &ExploitData) -> MemOpResult<usize> {
    match data {
        ExploitData::Aob(aob_data) => Ok(aob_data.var_mem.addr),
    }
}

/// Default implementation of ExploitImpl for AOB-based exploits
#[cfg(feature = "aob-injection")]
impl<T: AobExploitImpl> ExploitImpl for T {
    fn exploit_type(&self) -> ExploitType {
        ExploitType::AobInjection
    }
    
    fn target(&self) -> &str {
        self.module_name()
    }
    
    fn init_data(&self, handle: &SafeHandle) -> Result<ExploitData> {
        let maybe_module = module_by_name(handle, self.module_name(), true, None)?;
        let module = maybe_module.ok_or(anyhow!("Could not get module {}.", self.module_name()))?;
        
        let aob_data = AobData {
            module_addr: module.0 as usize,
            hook_mem: allocate_memory(handle, self.hook_alloc_size())?,
            var_mem: allocate_memory(handle, self.var_size())?,
            pattern: self.pattern().to_vec(),
            var_size: self.var_size(),
            hook_alloc_size: self.hook_alloc_size(),
            addr: None,
            found_bytes: None,
        };
        
        Ok(ExploitData::Aob(aob_data))
    }
    
    fn execute(&self, handle: &SafeHandle, data: &mut ExploitData) -> Result<()> {
        let aob_data = match data {
            ExploitData::Aob(aob_data) => aob_data,
        };
        
        let maybe_module = module_by_name(handle, self.module_name(), true, None)?;
        let module = maybe_module.ok_or(anyhow!("Could not get module {}.", self.module_name()))?;
        
        let module_info: MODULEINFO = get_module_info(handle, module, None)?;
        change_memory_protection(
            handle,
            module.0 as usize,
            module_info.SizeOfImage as usize,
            None,
            PAGE_READWRITE,
        )?;

        let bytes = read_bytes(
            handle,
            module.0 as usize,
            module_info.SizeOfImage as usize,
            None,
        )?;

        let matches = find_pattern_in_bytes(bytes, aob_data.pattern.clone())?;

        // Update addr and found_bytes
        (aob_data.addr, aob_data.found_bytes) = match matches.first() {
            Some((a, b)) => (Some(module.0 as usize + a.to_owned()), Some(b.to_owned())),
            None => return Err(anyhow!("Pattern not found")),
        };

        let hook_bytes = self.build_hook(aob_data)?;
        let jump_bytes = self.build_jmp(aob_data)?;

        let addr = aob_data.addr.ok_or(anyhow!(
            "Inject point address was not found. This should not be possible."
        ))?;

        write_bytes(
            handle,
            aob_data.hook_mem.addr as usize,
            &hook_bytes,
            None,
        )?;

        write_bytes(handle, addr, &jump_bytes, None)?;

        Ok(())
    }
    
    fn cleanup(&self, handle: &SafeHandle, data: &ExploitData) -> Result<()> {
        let aob_data = match data {
            ExploitData::Aob(aob_data) => aob_data,
        };
        
        let inject_addr = match aob_data.addr {
            None => return Ok(()),
            Some(a) => a as usize,
        };

        match &aob_data.found_bytes {
            Some(found_bytes) => {
                write_bytes(
                    handle,
                    inject_addr,
                    &create_unhook_bytes(self.pattern(), found_bytes),
                    None,
                )?;
            }
            None => {
                return Err(anyhow!(
                    "Unhook called without pattern scanned and match found."
                ))
            }
        }

        Ok(())
    }
    
    fn is_active(&self, data: &ExploitData) -> bool {
        match data {
            ExploitData::Aob(aob_data) => aob_data.addr.is_some(),
        }
    }
}

