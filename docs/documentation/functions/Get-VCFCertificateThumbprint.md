# Get-VCFCertificateThumbprint

## Synopsis

Retrieves certificate thumbprints for ESXi hosts or vCenter Server instances.

## Syntax

## For ESXi Hosts

```powershell
Get-VCFCertificateThumbprint [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-esxiFqdn] <String> [<CommonParameters>]
```

## For vCenter Server

```powershell
Get-VCFCertificateThumbprint [-vcenter] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [[-issuer] <String>] [<CommonParameters>]
```

## Description

The `Get-VCFCertificateThumbprint` cmdlet retrieves certificate thumbprints for ESXi hosts or vCenter Server instances.

## Examples

### Example 1

```powershell
Get-VCFCertificateThumbprint -esxi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
```

This example retrieves the ESXi host's certificate thumbprint for an ESXi host with the FQDN of sfo01-m01-esx01.sfo.rainpole.io.

### Example 2

```powershell
Get-VCFCertificateThumbprint -vcenter -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
```

This example retrieves the certificate thumbprints for the vCenter Server instance belonging to the domain sfo-m01.

### Example 3

```powershell
Get-VCFCertificateThumbprint -vcenter -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -issuer rainpole
```

This example retrieves the vCenter Server instance's certificate thumbprints for the vCenter Server instance belonging to domain sfo-m01 and a matching issuer "rainpole".

## Parameters

### -esxi

Retrieve the certificate thumbprint for ESXi host.

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

### -vcenter

Retrieve the certificate thumbprint for vCenter Server.

```yaml
Type: SwitchParameter
Parameter Sets: (vcenter)
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
Position: 1
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
Position: 2
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
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The FQDN of the ESXi host to retrieve the certificate thumbprint.

```yaml
Type: String
Parameter Sets: (esxi)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -domain

The name of the workload domain to retrieve the vCenter Server instance's certificate thumbprints from.

```yaml
Type: String
Parameter Sets: (vcenter)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -issuer

The name of the issuer to match with the vCenter Server instance's certificate thumbprints.

```yaml
Type: String
Parameter Sets: (vcenter)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
