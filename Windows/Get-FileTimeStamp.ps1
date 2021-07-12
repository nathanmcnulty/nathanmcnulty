Function Get-FileTimeStamp {
    <#
        .SYSNOPSIS
            Retrieves the timestamps for a given file.

        .DESCRIPTION
            Retrieves the timestamps for a given file. This not only shows the LastAccess, LastWrite and Creation timestamps, 
            but also shows the ChangeTime timestamp, which is not viewable just by looking at the properties of a file.

        .PARAMETER File
            Name of the file to get timestamps from.

        .NOTES
            Name: Get-FileTimeStamp
            Author: Boe Prox
            Version History:
                1.3 -- Boe Prox 18 Sept 2014
                    - Fixed bug that affected systems running PowerShell V4 under .Net 4.5
                1.2 -- Boe Prox 22 Aug 2014
                    - FileInformationClass enum had underlying type of uint16 when it needed to be uint32 to work properly 
                1.1 -- Boe Prox 15 Aug 2014
                    - Replaced C# compiled code in favor of using Reflection to dynamically build out the various 
                      components used in this function such as Structs, Enums and the pinvoke code. 
                1.0 -- Boe Prox 26 Feb 2013 
                    - Initial Creation


        .LINK
            http://learn-powershell.net

        .INPUTS
            System.String

        .OUPUTS
            None

        .EXAMPLE
            Get-FileTimeStamp -File 'SystemError.txt'
            CreationDate   : 2/13/2013 7:56:13 AM
            ChangeTime     : 2/26/2013 8:49:28 AM
            LastWriteTime  : 2/13/2013 7:56:13 AM
            LastAccessTime : 2/26/2013 8:48:00 AM
            FileName       : C:\users\Administrator\desktop\SystemError.txt


            Description
            -----------
            Displays all timestamps for the file SystemError.txt


    #>
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True)]
        [string[]]$File = "C:\users\proxb\desktop\SystemError.txt"
    )
    Begin {
        #region Debug Information
        $PSBoundParameters.GetEnumerator() | ForEach {
            Write-Verbose ("{0}" -f $_)
        }
        Write-Verbose ("Using ParameterSetName: {0}" -f $PSCmdlet.ParameterSetName)
        #endregion Debug Information

        #region Create Win32 API Object
        Try {
            [void][ntdll]
        } Catch {
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TimeStampModule', $False)
            #endregion Module Builder

            #region ENUMs
            $EnumBuilder = $ModuleBuilder.DefineEnum('FileInformationClass', 'Public', [UInt32])
            # Define values of the enum
            [void]$EnumBuilder.DefineLiteral('FileDirectoryInformation', [UInt32] 1)
            [void]$EnumBuilder.DefineLiteral('FileBasicInformation', [UInt32] 4)
            [void]$EnumBuilder.DefineLiteral('FileModeInformation', [UInt32] 16)
            [void]$EnumBuilder.DefineLiteral('FileHardLinkInformation', [UInt32] 46)

            #Create ENUM Type
            [void]$EnumBuilder.CreateType()
            #endregion ENUMs

            #region STRUCTs

            #region IOStatusBlock
            #Define STRUCT
            $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
            $TypeBuilder = $ModuleBuilder.DefineType('IOStatusBlock', $Attributes, [System.ValueType], 1, 0x10)
            [void]$TypeBuilder.DefineField('status', [UInt64], 'Public')
            [void]$TypeBuilder.DefineField('information', [UInt64], 'Public')

            #Create STRUCT Type
            [void]$TypeBuilder.CreateType()
            #endregion IOStatusBlock

            #region FileBasicInformation
            #Define STRUCT
            $Attributes = 'AutoLayout, AnsiClass, Class, ExplicitLayout, Sealed, BeforeFieldInit,public'
            $TypeBuilder = $ModuleBuilder.DefineType('FileBasicInformation', $Attributes, [System.ValueType], 8, 0x28)
            $CreateTimeField = $TypeBuilder.DefineField('CreationTime', [UInt64], 'Public')
            $CreateTimeField.SetOffset(0)
            $LastAccessTimeField = $TypeBuilder.DefineField('LastAccessTime', [UInt64], 'Public')
            $LastAccessTimeField.SetOffset(8)
            $LastWriteTimeField = $TypeBuilder.DefineField('LastWriteTime', [UInt64], 'Public')
            $LastWriteTimeField.SetOffset(16)
            $ChangeTimeField = $TypeBuilder.DefineField('ChangeTime', [UInt64], 'Public')
            $ChangeTimeField.SetOffset(24)
            $FileAttributesField = $TypeBuilder.DefineField('FileAttributes', [UInt64], 'Public')
            $FileAttributesField.SetOffset(32)

            #Create STRUCT Type
            [void]$TypeBuilder.CreateType()
            #endregion FileBasicInformation

            #endregion STRUCTs

            #region DllImport
            $TypeBuilder = $ModuleBuilder.DefineType('ntdll', 'Public, Class')

            #region NtQueryInformationFile Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'NtQueryInformationFile', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [IntPtr], #Method Return Type
                [Type[]] @([Microsoft.Win32.SafeHandles.SafeFileHandle], [IOStatusBlock], [IntPtr] ,[UInt16], [FileInformationClass]) #Method Parameters
            )

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            )

            $FieldValueArray = [Object[]] @(
                'NtQueryInformationFile', #CASE SENSITIVE!!
                $True
            )

            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('ntdll.dll'),
                $FieldArray,
                $FieldValueArray
            )

            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            #endregion NtQueryInformationFile Method

            [void]$TypeBuilder.CreateType()
            #endregion DllImport
        }
        #endregion Create Win32 API object
    }
    Process {
        #region Check file name
        ForEach ($item in $File) {
            If (-Not ([uri]$item).IsAbsoluteUri) {
                Write-Verbose ("{0} is not a full path, using current directory: {1}" -f $item,$pwd)
                $item = (Join-Path $pwd ($item -replace "\.\\",""))
            }
            #endregion Check file name
            $fbi = New-Object "FileBasicInformation"
            $iosb = New-Object "IOStatusBlock"

            Try {
                $FileStream = [System.IO.File]::Open($Item,'Open','Read','ReadWrite')

                # Initialize unmanaged memory for FileBasicInformation Struct
                $p_fbi = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($fbi))

                # Pull file timestamps from file
                $iprc = [ntdll]::NtQueryInformationFile($FileStream.SafeFileHandle, $iosb, $p_fbi, 
                    [System.Runtime.InteropServices.Marshal]::SizeOf($fbi), [FileInformationClass]::FileBasicInformation
                )

                # Check to make sure no issues occurred
                $IsOK = (($iprc -eq [intptr]::Zero) -AND ($iosb.status -eq 0))

                If ($IsOK) {
                    # Pull data from unmanaged memory block into a usable object
                    $fbi = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p_fbi, [System.Type][FileBasicInformation])
                    $Object = [pscustomobject]@{
                        FullName = $FileStream.Name
                        CreationTime = [datetime]::FromFileTime($fbi.CreationTime)
                        LastAccessTime = [datetime]::FromFileTime($fbi.LastAccessTime)
                        LastWriteTime = [datetime]::FromFileTime($fbi.LastWriteTime)
                        ChangeTime = [datetime]::FromFileTime($fbi.ChangeTime)
                    }
                    $Object.PSTypeNames.Insert(0,'System.Io.FileTimeStamp')
                    Write-Output $Object
                } Else {
                    Write-Warning "$($Item): $(New-Object ComponentModel.Win32Exception)"
                }
                #region Perform Cleanup
                $FileStream.Close()
                # Deallocate memory
                If ($p_fbi -ne [intptr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($p_fbi)
                }
                #endregion Perform Cleanup
            } Catch {
                Write-Warning "$($item) $_"
            }
        }
        #endregion Get file timestamps
    }
    End {}
}
