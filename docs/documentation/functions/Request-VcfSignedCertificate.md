# Request-VcfSignedCertificate

## Synopsis

Requests SDDC Manager to connect to certificate authority to sign the certificate signing request files and to store the signed certificates.

## Syntax

```powershell
Request-VcfSignedCertificate [-server] <String> [-user] <String> [-pass] <String> [-workloadDomain] <String> [-certAuthority] <String>[<CommonParameters>]
```

## Description

The `Request-VcfSignedCertificate` will request SDDC Manager to connect to the certificate authority to sign the generated certificate signing request files for all components associated with the given workload domain

## Examples

### Example 1

```powershell
Request-VcfSignedCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name] -certAuthority Microsoft
```

This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed by Microsft CA.

### Example 2

```powershell
Request-VcfSignedCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name] -certAuthority OpenSSL
```

This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed by OpenSSL CA.

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

### -certAuthority

The type of Certificate Authority to be configured. One of: `Microsoft`, `OpenSSL`.

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
