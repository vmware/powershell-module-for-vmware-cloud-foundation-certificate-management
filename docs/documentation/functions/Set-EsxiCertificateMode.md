# Set-EsxiCertificateMode

## Synopsis

Sets the certificate management mode in vCenter Server for the ESXi hosts in a workload domain.

## Syntax

```powershell
Set-EsxiCertificateMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-mode] <String> [<CommonParameters>]
```

## Description

The `Set-EsxiCertificateMode` cmdlet sets the certificate management mode in vCenter Server for the ESXi hosts in a workload domain.

## Examples

### Example 1

```powershell
Set-EsxiCertificateMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -mode custom
```

This example sets the certificate management mode to custom in vCenter Server for the ESXi hosts in workload domain sfo-m01.

## Parameters

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

### -domain

The name of the workload domain to set the vCenter Server instance certificate management mode setting for.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -mode

The certificate management mode to set in vCenter Server.
One of "custom" or "vmca".

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
