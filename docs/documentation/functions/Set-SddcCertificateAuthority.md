# Set-SddcCertificateAuthority

## SYNOPSIS
Configure Microsoft Certificate Authority in SDDC Manager

## SYNTAX

```
Set-SddcCertificateAuthority [-server] <String> [-user] <String> [-pass] <String> [-certAuthorityFqdn] <String>
 [-certAuthorityUser] <String> [-certAuthorityPass] <String> [-certAuthorityTemplate] <String>
 [<CommonParameters>]
```

## DESCRIPTION
The Set-SddcCertificateAuthority will configure Microsoft Certificate Authority as SDDC Manager's Certificate Authority.

## EXAMPLES

### EXAMPLE 1
```
Set-SddcCertificateAuthority -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -certAuthorityFqdn rpl-ad01.rainpole.io -certAuthorityUser svc-vcf-ca -certAuthorityPass VMw@re1! -certAuthorityTemplate VMware
This example will configure Microsoft Certificate Authority rpl-ad01.rainpole.io in SDDC Manger.
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

### -certAuthorityFqdn
The fully qualified domain name of the Microsoft Certificate Authority.

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

### -certAuthorityUser
The username to authenticate to the Microsoft Certificate Authority.

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

### -certAuthorityPass
The password to authenticate to the Microsoft Certificate Authority.

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

### -certAuthorityTemplate
The Certificate Template Name to be used with the Microsoft Certificate Authority.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).