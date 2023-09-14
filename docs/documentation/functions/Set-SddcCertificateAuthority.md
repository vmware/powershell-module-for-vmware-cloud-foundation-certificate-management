# Set-SddcCertificateAuthority

## Synopsis

Sets the certificate authority in SDDC Manager to use a Microsoft Certificate Authority or an OpenSSL Certificate Authority.

## Syntax

```powershell
Set-SddcCertificateAuthority [-server] <String> [-user] <String> [-pass] <String> [-certAuthorityFqdn] <String> [-certAuthorityUser] <String> [-certAuthorityPass] <String> [-certAuthorityTemplate] <String> [<CommonParameters>]
```

## Description

The `Set-SddcCertificateAuthority` will configure Microsoft Certificate Authority or OpenSSL Certificate Authority as SDDC Manager's Certificate Authority.

## Examples

### Example 1

```powershell
Set-SddcCertificateAuthority -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -certAuthorityFqdn rpl-ad01.rainpole.io -certAuthorityUser svc-vcf-ca -certAuthorityPass VMw@re1! -certAuthorityTemplate VMware
```

This example will configure Microsoft Certificate Authority rpl-ad01.rainpole.io in SDDC Manger.

```powershell
Set-SddcCertificateAuthority -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -commonName "sfo-vcf01.sfo.rainpole.io" -organization "Rainpole" -organizationUnit "Platform Engineering" -locality "San Francisco" -state CA -country US
```

This example will configure an OpenSSL Certificate Authority in SDDC Manager.


## Parameters

### -certAuthority

The type of Certificate Authority to be configured - Microsoft or OpenSSL

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

### -server

The fully qualified domain name of the SDDC Manager instance.

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

### -user

The username to authenticate to the SDDC Manager instance.

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

### -pass

The password to authenticate to the SDDC Manager instance.

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

### -certAuthorityFqdn

The fully qualified domain name of the Microsoft Certificate Authority.

```yaml
Type: String
Parameter Sets: (microsoft)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certAuthorityUser

The username to authenticate to the Microsoft Certificate Authority.

```yaml
Type: String
Parameter Sets: (microsoft)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certAuthorityPass

The password to authenticate to the Microsoft Certificate Authority.

```yaml
Type: String
Parameter Sets: (microsoft)
Aliases:

Required: True
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certAuthorityTemplate

The Certificate Template Name to be used with the Microsoft Certificate Authority.

```yaml
Type: String
Parameter Sets: (microsoft)
Aliases:

Required: True
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -commonName

Specifies the common name for the OpenSSL Certificate Authority.

```yaml
Type: String
Parameter Sets: (openssl)
Aliases:

Required: True
Position: 9
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -organization

Specifies the organization name for the OpenSSL Certificate Authority.

```yaml
Type: String
Parameter Sets: (openssl)
Aliases:

Required: True
Position: 10
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -organizationUnit

Specifies the organization unit for the OpenSSL Certificate Authority.

```yaml
Type: String
Parameter Sets: (openssl)
Aliases:

Required: True
Position: 11
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -locality

Specifies the locality for the OpenSSL Certificate Authority.

```yaml
Type: String
Parameter Sets: (openssl)
Aliases:

Required: True
Position: 12
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```


### -state

Specifies the state for the OpenSSL Certificate Authority.

```yaml
Type: String
Parameter Sets: (openssl)
Aliases:

Required: True
Position: 13
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -country

Specifies the country for the OpenSSL Certificate Authority.

```yaml
Type: String
Parameter Sets: (openssl)
Aliases:

Required: True
Position: 14
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
