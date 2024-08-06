# Install-VCFCertificate

## Synopsis

Installs the signed certificates for all components associated with the given workload domain, or an ESXi Host or for each ESXi host in a given cluster.

## Syntax

### Installing Certificates for a Workload Domain

```powershell
Install-VCFCertificate [-sddcManager] [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [<CommonParameters>]
```

### Installing Certificates ESXi Hosts in a Cluster

```powershell
Install-VCFCertificate [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-vsanDataMigrationMode] <String> [-migratePowerOffVMs] [-certificateDirectory] <String> [-certificateFileExt] <String> [[-timeout] <String>] [-NoConfirmation] [<CommonParameters>]
```

### Installing a Certificate for an ESXi Host

```powershell
Install-VCFCertificate [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-esxiFqdn] <String> [-vsanDataMigrationMode] <String>[-migratePowerOffVMs] [-certificateDirectory] <String> [-certificateFileExt] <String> [[-timeout] <String>] [-NoConfirmation] [<CommonParameters>]
```

## Description

The `Install-VCFCertificate` will install the signed certificates for all components associated with the given workload domain when used with the `-sddcManager` switch.

The `Install-VCFCertificate` will replace the certificate for an ESXi host or for each ESXi host in a cluster when used with the `-esxi` switch.

When used with the `-esxi` switch, this cmdlet:

- You must provide the directory containing the signed certificate files.
- Certificate names should be in format `<FQDN>.crt` (_e.g._, `sfo01-m01-esx01.sfo.rainpole.io.crt`.)
- The workflow will put the ESXi host in maintenance mode with full data migration, disconnect the ESXi host from the vCenter Server, replace the certificate, restart the ESXi host, and the exit maintenance mode once the ESXi host is online.

## Examples

### Example 1

```powershell
Install-VCFCertificate -sddcManager -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01
```

This example will connect to SDDC Manager to install the signed certificates for a given workload domain.

### Example 2

```powershell
Install-VCFCertificate -esxi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -migratePowerOffVMs -vsanDataMigrationMode EnsureAccessibility -certificateDirectory F:\certificates -certificateFileExt ".cer"
```

This example will install the certificate to the ESXi host sfo01-m01-esx01.sfo.rainpole.io in sfo-m01 workload domain using the provided path.

For VMware Cloud Foundation 5.1 or earlier, the ESXi host will enter maintenance mode with vSAN data migration Mode set to `EnsureAccessibility`. Any powered off virtual machines will be migrated off the ESXi host prior to entering maintenance mode.

### EXAMPLE 3

```powershell
Install-VCFCertificate -esxi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -certificateDirectory F:\certificates -certificateFileExt ".cer"
```

This example will install certificates for each ESXi host in the sfo-m01-cl01 cluster within the sfo-m01 workload domain, using the provided path.

For VMware Cloud Foundation 5.2 or later, the `vsanDataMigrationMode` option is no longer applicable.

For VMware Cloud Foundation 5.1 or earlier, by default the ESXi hosts will enter maintenance mode with vSAN data migration Mode set to `Full data migration`. Any powered off virtual machines will not be migrated off the ESXi hosts prior to entering maintenance mode.

### EXAMPLE 4

```powershell
Install-VCFCertificate -esxi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -certificateDirectory F:\certificates -certificateFileExt ".cer" -uploadPrivateKey
```

This example will install private keys and certificates for each ESXi host in the sfo-m01-cl01 cluster within the sfo-m01 workload domain, using the provided path.

The `uploadPrivateKey` parameter is only validated for VMware Cloud Foundation version is 5.2 or later.

## Parameters

### -esxi

Switch to indicate that the certificate is to be installed on an ESXi host.

```yaml
Type: SwitchParameter
Parameter Sets: (esxi)
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -sddcManager

Switch to indicate that the certificate is to be installed for all components associated with the given workload domain, excluding ESXi hosts.

```yaml
Type: SwitchParameter
Parameter Sets: (sddcManager)
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -server

The fully qualified domain name of the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -user

The username to authenticate to the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -pass

The password to authenticate to the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -domain

The name of the workload domain in which the certificate is requested to be installed or where the ESXi host is located.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -cluster

The name of the cluster in which the ESXi host is located.

```yaml
Type: String
Parameter Sets: (esxi)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The fully qualified domain name of the ESXi host.

```yaml
Type: String
Parameter Sets: (esxi)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certificateDirectory

The directory containing the signed certificate files.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certificateFileExt

The file extension of the certificate files.
One of ".crt", ".cer", ".pem", ".p7b", or ".p7c".

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -timeout

The timeout in seconds for putting the ESXi host in maintenance mode.
Default is 18000 seconds (5 hours).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 18000
Accept pipeline input: False
Accept wildcard characters: False
```

### -vsanDataMigrationMode

The vSAN Data Migration mode validate value ("Full", "EnsureAccessibility").

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -migratePowerOffVMs

Option to decide if power off virtual machines and suspended virtual machines will be migrated to other ESXi hosts when the ESXi host goes into maintenance mode.

```yaml
Type: Switch
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoConfirmation

Option to skip Confirmation warning when performing the ESXi host certificate replacement.

```yaml
Type: Switch
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -uploadPrivateKey

Option to upload an external private key when performing the ESXi host certificate replacement. Supported on VMware Cloud Foundation 5.2 or later

```yaml
Type: Switch
Parameter Sets: (ALL)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
