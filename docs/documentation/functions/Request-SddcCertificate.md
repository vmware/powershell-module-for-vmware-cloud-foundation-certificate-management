# Request-SddcCertificate

## Synopsis

Requests SDDC Manager to connect to certificate authority to sign the certificate signing request files and to store the signed certificates.

## Syntax

```powershell
Request-SddcCertificate [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [<CommonParameters>]
```

## Description

The `Request-SddcCertificate` will request SDDC Manager to connect to the certificate authority to sign the generated certificate signing request files for all components associated with the given workload domain

## Examples

### Example 1

```powershell
Request-SddcCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01
```

This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed.

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

The name of the workload domain in which the certificate is requested to be signed.

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

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
