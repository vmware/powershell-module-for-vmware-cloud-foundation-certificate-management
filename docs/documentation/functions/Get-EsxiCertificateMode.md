# Get-EsxiCertificateMode

## Synopsis

Retrieves the certificate management mode value from the vCenter instance for a workload domain.

## Syntax

```powershell
Get-EsxiCertificateMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [<CommonParameters>]
```

## Description

The `Get-EsxiCertificateMode` cmdlet retrieves the certificate management mode value from vCenter instance for a workload domain.

## Examples

### Example 1

```powershell
Get-EsxiCertificateMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example retrieves the certificate management mode value for the vCenter instance for the workload domain.

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

The name of the workload domain to retrieve the certificate management mode value for.

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).