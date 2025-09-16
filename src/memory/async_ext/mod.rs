pub mod read;
pub mod utils;
pub mod write;

#[cfg(feature = "async")]
/// Async version of zhol::memory::read::<T>() for reading typed values from process memory.
/// 
/// # Arguments
/// * `hook` - Reference to the async hook containing process handle and memory information
/// * `context` - Memory operation context containing offset and pointer settings
/// * `base_opt` - Optional base address override, if None uses the hook's memory address
/// 
/// # Returns
/// Returns the read value of type T wrapped in a MemOpResult
/// 
/// # Example
/// ```rust,norun
/// use std::time::Duration;
/// 
/// let hook = get_process_hook(process_id)?;
/// let context = MemOpContext::new(0x0, 0x100, false, Some(Duration::from_secs(1)));
/// 
/// // Read an i32 value from memory
/// let value: i32 = read::<i32>(&hook, &context, None).await?;
/// println!("Read value: {}", value);
/// ```
pub async fn read<T: crate::memory::transmute::ZholTyped<T> + Send + Sync>(
    hook: &crate::hooks::async_ext::AsyncZholHook,
    context: &crate::memory::MemOpContext,
    base_opt: Option<usize>,
) -> crate::MemOpResult<T> {
    let data = hook.data().read();
    let var_mem_addr = crate::hooks::get_var_mem_addr(&data)?;
    let base = match base_opt {
        Some(b) => b,
        None => var_mem_addr,
    };
    let ptr: usize = match context.at_pointer {
        true => crate::memory::async_ext::read::read_value::<i32>(hook, base, context.timeout).await? as usize,
        false => base,
    };

    drop(data); // We don't want to keep data anymore in the event of read_value::<T>() hanging. -S

    crate::memory::async_ext::read::read_value::<T>(hook, ptr + context.offset, context.timeout).await
}

#[cfg(feature = "async")]
/// Async version of zhol::memory::write::<T>() for writing typed values to process memory.
/// 
/// # Arguments
/// * `hook` - Reference to the async hook containing process handle and memory information
/// * `value` - The value to write to memory
/// * `context` - Memory operation context containing offset and pointer settings
/// * `base_opt` - Optional base address override, if None uses the hook's memory address
/// 
/// # Returns
/// Returns MemOpResult<()> indicating success or failure of the write operation
/// 
/// # Example
/// ```rust,norun
/// use std::time::Duration;
/// 
/// let hook = get_process_hook(process_id)?;
/// let context = MemOpContext::new(0x0, 0x100, false, Some(Duration::from_secs(1)));
/// 
/// // Write an i32 value to memory
/// let new_value: i32 = 42;
/// write(&hook, new_value, &context, None).await?;
/// 
/// // Verify the write
/// let read_back: i32 = read::<i32>(&hook, &context, None).await?;
/// assert_eq!(read_back, new_value);
/// ```
pub async fn write<T: crate::memory::transmute::ZholTyped<T> + Send + Sync>(
    hook: &crate::hooks::async_ext::AsyncZholHook,
    value: T,
    context: &crate::memory::MemOpContext,
    base_opt: Option<usize>,
) -> crate::MemOpResult<()> {
    let data = hook.data().read();
    let var_mem_addr = crate::hooks::get_var_mem_addr(&data)?;
    let base = match base_opt {
        Some(b) => b,
        None => var_mem_addr,
    };
    let ptr: usize = match context.at_pointer {
        true => {
            crate::memory::async_ext::read::read_value::<i32>(hook, base, context.timeout).await?
                as usize
        }
        false => base,
    };

    drop(data);

    crate::memory::async_ext::write::write_value(hook, ptr + context.offset, value, context.timeout).await
}