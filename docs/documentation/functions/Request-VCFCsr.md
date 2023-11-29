# Request-VCFCsr

## Synopsis

Requests SDDC Manager to generate and store certificate signing request (CSR) files or requests a certificate signing request for either an ESXi host or a for each ESXi host in a cluster and saves it to file(s) in a directory.

## Syntax

### Certificate Signing Requests for a Workload Domain

```powershell
Request-VCFCsr [-sddcManager] [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-country] <String> [-keySize] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [-email] <String> [<CommonParameters>]
```

### Certificate Signing Request for all ESXi Hosts in a Cluster

```powershell
Request-VCFCsr [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-outputDirectory] <String> [-country] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [<CommonParameters>]
```

### Certificate Signing Request for an ESXi Host

```powershell
Request-VCFCsr [-esxi] [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] [-esxiFqdn] <String> [-outputDirectory] <String> [-country] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [<CommonParameters>]
```

## Description

 The `Request-VCFCsr` will request SDDC Manager to generate certificate signing request files for all components associated with the given domain when used with `-sddcManager` switch.
 The `Request-VCFCsr` will generate the certificate signing request for ESXi host(s) and saves it to file(s) in an output directory when used with `-esxi` switch.

The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-password` values.

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that the workload domain exists in the SDDC Manager inventory.
- Validates that network connectivity and authentication is possible to vCenter Server.
- Defines possible country codes. [Reference](https://www.digicert.com/kb/ssl-certificate-country-codes.htm)

When used with the `-esxi` switch, this cmdlet:

- Gathers the ESXi hosts from the cluster.
- Requests the ESXi host CSR and saves it in the output directory as `<esxi-host-fqdn>.csr` (_e.g._, `sfo01-m01-esx01.sfo.rainpole.io.csr`.)

## Examples

### Example 1

```powershell
Request-VCFCsr -esxi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -country US -locality "Palo Alto" -organization "Rainpole" -organizationUnit "Engineering" -stateOrProvince "California" -outputDirectory F:\csr
```

This example generates CSRs and stores them in the provided output directory for all ESXi hosts in the cluster sfo-m01-cl01 with the specified fields.

### Example 2

```powershell
Request-VCFCsr -sddcManager -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-w01 -country US -keysize "3072" -locality "San Francisco" -organization "Rainpole" -organizationUnit "IT" -stateOrProvince "California" -email "admin@rainpole.io"
```

This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

## Parameters

### -esxi

Switch to request and save certificate signing request files for ESXi hosts

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

The fully qualified domain name of the ESXi host to request certificate signing request (CSR) for.

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

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
