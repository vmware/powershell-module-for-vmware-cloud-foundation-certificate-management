# Request-VcfCsr

## Synopsis

Requests SDDC Manager to generate and store certificate signing request (CSR) files or requests a certificate signing request for either an ESX host or a for each ESX host in a cluster and saves it to file(s) in a directory.

## Syntax

### Certificate Signing Requests for a Workload Domain

```powershell
Request-VcfCsr [-sddcManager] [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-country] <String> [-keySize] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [-email] <String> [<CommonParameters>]
```

### Certificate Signing Request for all ESX Hosts in a Cluster

```powershell
Request-VcfCsr [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-outputDirectory] <String> [-country] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [<CommonParameters>]
```

### Certificate Signing Request for an ESX Host

```powershell
Request-VcfCsr [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] [-esxiFqdn] <String> [-outputDirectory] <String> [-country] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [<CommonParameters>]
```

## Description

 The `Request-VcfCsr` will request SDDC Manager to generate certificate signing request files for all components associated with the given domain when used with `-sddcManager` switch.
 The `Request-VcfCsr` will generate the certificate signing request for ESX host(s) and saves it to file(s) in an output directory when used with `-esxi` switch.

The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-password` values.

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that the workload domain exists in the SDDC Manager inventory.
- Validates that network connectivity and authentication is possible to vCenter.
- Defines possible country codes. [Reference](https://www.digicert.com/kb/ssl-certificate-country-codes.htm)

When used with the `-esxi` switch, this cmdlet:

- Gathers the ESX hosts from the cluster.
- Requests the ESX host CSR and saves it in the output directory as `<esxi-host-fqdn>.csr` (_e.g._, `sfo01-m01-esx01.sfo.rainpole.io.csr`.)

## Examples

### Example 1

```powershell
Request-VcfCsr -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -country [country] -locality [locality] -organization [organization] -organizationUnit [organization_unit] -stateOrProvince [state_or_province] -outputDirectory [output_path]
```

This example generates CSRs and stores them in the provided output directory for all ESX hosts in the cluster with the specified fields.

### Example 2

```powershell
Request-VcfCsr -sddcManager -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -country [country] -keysize [keysize] -locality [locality] -organization [organization] -organizationUnit [organization_unit] -stateOrProvince [state_or_province] -email [email_address]
```

This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

## Parameters

### -esxi

Switch to request and save certificate signing request files for ESX hosts

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

Switch to request and store certificate signing request files on SDDC Manager

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

The name of the workload domain in which the cluster is located.

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

The name of the cluster in which the ESX host is located.

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

The fully qualified domain name of the ESX host to request certificate signing request (CSR) for.

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

### -outputDirectory

The directory to save the certificate signing request (CSR) files.

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

### -country

The country code for the certificate signing request (CSR).

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

### -locality

The locality for the certificate signing request (CSR).

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

### -organization

The organization for the certificate signing request (CSR).

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

### -organizationUnit

The organization unit for the certificate signing request (CSR).

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

### -stateOrProvince

The state or province for the certificate signing request (CSR).

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

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).