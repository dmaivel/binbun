/* A WDM driver, built with MSVC and the WDK's kernel-mode flags (Debug
 * x64: see scripts/build-driver-fixture.bat) as driver-x86_64.sys and its
 * PDB: wide device names and narrow DbgPrint formats, which the WDK's
 * `-cbstring` puts in .text, after the code; a few kernel calls
 * (IoCreateDevice's seven parameters); and a gs-relative read
 * (KeGetCurrentThread: the KPCR's current thread). */
#include <ntddk.h>

#define DRV_DEVICE_NAME L"\\Device\\BinbunDrv"
#define DRV_LINK_NAME L"\\DosDevices\\BinbunDrv"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DrvUnload;
DRIVER_DISPATCH DrvCreateClose;

__declspec(noinline)
static ULONG_PTR
DrvThreadTag(VOID)
{
    PKTHREAD thread = KeGetCurrentThread();
    return (ULONG_PTR)thread ^ (ULONG_PTR)PsGetCurrentProcessId();
}

_Use_decl_annotations_
NTSTATUS
DrvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING link;

    RtlInitUnicodeString(&link, DRV_LINK_NAME);
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("BinbunDrv: unloaded\n");
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name;
    UNICODE_STRING link;
    PDEVICE_OBJECT device;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("BinbunDrv: thread tag %p\n", (PVOID)DrvThreadTag());
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvCreateClose;
    DriverObject->DriverUnload = DrvUnload;

    RtlInitUnicodeString(&name, DRV_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlInitUnicodeString(&link, DRV_LINK_NAME);
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
