# Set-EsxiCertificateMode

## Synopsis

Sets the certificate management mode in vCenter for the ESX hosts in a workload domain.

## Syntax

```powershell
Set-EsxiCertificateMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-mode] <String> [<CommonParameters>]
```

## Description

The `Set-EsxiCertificateMode` cmdlet sets the certificate management mode in vCenter for the ESX hosts in a workload domain.

## Examples

### Example 1

```powershell
Set-EsxiCertificateMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -mode custom
```

This example sets the certificate management mode to custom in vCenter for the ESX hosts in workload domain.

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

The name of the workload domain to set the vCenter instance certificate management mode setting for.

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

The certificate management mode to set in vCenter.
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
