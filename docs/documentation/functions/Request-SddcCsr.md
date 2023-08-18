# Request-SddcCsr

## SYNOPSIS
Request SDDC Manager to generate Certificate Signing Request files and to store the Certificate Signing Request files.

## SYNTAX

```
Request-SddcCsr [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String>
 [-country] <String> [-keySize] <String> [-locality] <String> [-organization] <String>
 [-organizationUnit] <String> [-stateOrProvince] <String> [-email] <String> [<CommonParameters>]
```

## DESCRIPTION
The Request-SddcCsr will request SDDC Manager to generate certifiate signing request files for all components associated with the given workload domain.

## EXAMPLES

### EXAMPLE 1
```
Request-SddcCsr -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01 -country US -keysize "3072" -locality "San Francisco" -organization "Rainpole" -organizationUnit "IT" -stateOrProvince "California" -email "admin@rainpole.io"
This example will request SDDC Manager to generate Certificate Signing Request files for all components associated with the given workload domain.
```

## PARAMETERS

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
The country code for the Certificate Signing Request (CSR).

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
The key size for the Certificate Signing Request (CSR).

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
The locality for the Certificate Signing Request (CSR).

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
The organization for the Certificate Signing Request (CSR).

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
The organization unit for the Certificate Signing Request (CSR).

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
The state or province for the Certificate Signing Request (CSR).

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
The contact email for the Certificate Signing Request (CSR).

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).