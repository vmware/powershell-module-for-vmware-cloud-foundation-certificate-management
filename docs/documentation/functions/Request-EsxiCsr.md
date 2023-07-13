# Request-EsxiCsr

## Synopsis

Requests a Certificate Signing Request (CSR) for an ESXi host or a for each ESXi host in a cluster and saves it to file(s) in a directory.

## Syntax

### cluster

```powershell
Request-EsxiCsr [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-outputDirectory] <String> [-country] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [<CommonParameters>]
```

### host

```powershell
Request-EsxiCsr [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] [-esxiFqdn] <String> [-outputDirectory] <String> [-country] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [<CommonParameters>]
```

## Description

The `Request-EsxiCsr` cmdlet will generate the Certificate Signing Request for ESXi host(s) and saves it to file(s) in an output directory.

The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-password` values.

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that the workload domain exists in the SDDC Manager inventory.
- Validates that network connectivity and authentication is possible to vCenter Server.
- Gathers the ESXi hosts from the cluster.
- Requests the ESXi host CSR and saves it in the output directory as `<esxi-host-fqdn>.csr` (_e.g._, `sfo01-m01-esx01.sfo.rainpole.io.csr`.)
- Defines possible country codes.

Reference: <https://www.digicert.com/kb/ssl-certificate-country-codes.htm>

## Examples

### Example 1

```powershell
Request-EsxiCsr -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -country US -locality "Palo Alto" -organization "VMware, Inc." -organizationUnit "Engineering" -stateOrProvince "California" -outputDirectory F:\csr
```

This example generates CSRs and stores them in the provided output directory for all ESXi hosts in the cluster sfo-m01-cl01 with the specified fields.

## Parameters

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
Parameter Sets: cluster
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The FQDN of the ESXi host to request Certificate Signing Request (CSR) for.

```yaml
Type: String
Parameter Sets: host
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -outputDirectory

The directory to save the Certificate Signing Request (CSR) files.

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

The country code for the Certificate Signing Request (CSR).

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

The locality for the Certificate Signing Request (CSR).

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

The organization for the Certificate Signing Request (CSR).

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

The organization unit for the Certificate Signing Request (CSR).

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

The state or province for the Certificate Signing Request (CSR).

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
