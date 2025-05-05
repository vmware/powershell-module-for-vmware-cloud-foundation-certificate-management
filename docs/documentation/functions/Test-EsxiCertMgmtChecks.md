# Test-EsxiCertMgmtChecks

## Synopsis

Run the checks required for ESX Certificate Management for a given cluster or an ESX host.

## Syntax

```powershell
Test-EsxiCertMgmtChecks [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-signedCertificate] <String> [[-esxiFqdn] <String>] [[-issuer] <String>] [<CommonParameters>]
```

## Description

The `Test-EsxiCertMgmtChecks` runs the checks required for ESX Certificate Management for a given cluster or an ESX host.

The following checks are run:

- Check ESX Certificate Mode
- Check ESX Lockdown Mode
- Confirm Certificate Authority in vCenter
- Check vSAN Health Status

## Examples

### Example 1

```powershell
Test-EsxiCertMgmtChecks -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -issuer [issuer_name] -signedCertificate [full_certificate_file_path]
```

This example runs the checks required for ESX Certificate Management for the cluster belonging to the domain.

### Example 2

```powershell
Test-EsxiCertMgmtChecks -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -esxiFqdn [esx_host_fqdn] -issuer [issuer_name] -signedCertificate [full_certificate_file_path]
```

This example runs the checks required for ESX Certificate Management for an ESX host belonging to the domain.

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

The name of the workload domain to retrieve the vCenter instance's certificate thumbprints from.

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

### -cluster

The name of the cluster in which the ESX host is located.

```yaml
Type: String
Parameter Sets: cluster
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -signedCertificate

The complete path for the root certificate file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -issuer

The name of the issuer to match with the thumbprint.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The fully qualified domain name of the ESX host.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).