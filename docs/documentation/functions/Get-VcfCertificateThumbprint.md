# Get-VcfCertificateThumbprint

## Synopsis

Retrieves certificate thumbprints for ESX hosts or vCenter instances.

## Syntax

### Certificate Thumbprint from an ESX Host

```powershell
Get-VcfCertificateThumbprint [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-esxiFqdn] <String> [<CommonParameters>]
```

### Certificate Thumbprint from a vCenter Instance

```powershell
Get-VcfCertificateThumbprint [-vcenter] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [[-issuer] <String>] [<CommonParameters>]
```

## Description

The `Get-VcfCertificateThumbprint` cmdlet retrieves certificate thumbprints for ESX hosts or vCenter instances.

## Examples

### Example 1

```powershell
Get-VcfCertificateThumbprint -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -esxiFqdn [esx_host_fqdn]
```

This example retrieves the ESX host's certificate thumbprint for an ESX host.

### Example 2

```powershell
Get-VcfCertificateThumbprint -vcenter -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
```

This example retrieves the certificate thumbprints for the vCenter instance belonging to the domain.

### Example 3

```powershell
Get-VcfCertificateThumbprint -vcenter -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -issuer [issuer_name]
```

This example retrieves the vCenter instance's certificate thumbprints for the vCenter instance belonging to domain and a matching issuer.

## Parameters

### -esxi

Switch to retrieve the certificate thumbprint for an ESX host.

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

Switch to retrieve the certificate thumbprints for a vCenter instance.

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

The fully qualified domain name of the ESX host to retrieve the certificate thumbprint.

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

The name of the workload domain to retrieve the vCenter instance's certificate thumbprints from.

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

The name of the issuer to match with the vCenter instance's certificate thumbprints.

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

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).