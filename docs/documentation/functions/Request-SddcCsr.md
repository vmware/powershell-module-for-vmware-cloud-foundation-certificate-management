# Request-SddcCsr

## Synopsis

Requests SDDC Manager to generate and store certificate signing request files.

## Syntax

```powershell
Request-SddcCsr [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-country] <String> [-keySize] <String> [-locality] <String> [-organization] <String> [-organizationUnit] <String> [-stateOrProvince] <String> [-email] <String> [<CommonParameters>]
```

## Description

The `Request-SddcCsr` will request SDDC Manager to generate certifiate signing request files for all components associated with the given workload domain.

The cmdlet connects to the SDDC Manager using the `-server`, `-user`, and `-password` values.

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that the workload domain exists in the SDDC Manager inventory.
- Defines possible country codes. [Reference](https://www.digicert.com/kb/ssl-certificate-country-codes.htm)

## Examples

### Example 1

```powershell
Request-SddcCsr -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01 -country US -keysize "3072" -locality "San Francisco" -organization "Rainpole" -organizationUnit "IT" -stateOrProvince "California" -email "admin@rainpole.io"
```

This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

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

### -workloadDomain

The name of the workload domain in which the certficates signing request to be generated.

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

### -country

The country code for the certificate signing request (CSR).

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

### -keySize

The key size for the certificate signing request (CSR).

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

### -locality

The locality for the certificate signing request (CSR).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 7
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
Position: 8
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
Position: 9
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
Position: 10
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -email

The contact email for the certificate signing request (CSR).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 11
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
