# Confirm-ESXiCertificateInstalled

## SYNOPSIS

Verify if the provided certificate is already on the ESXi host.

## SYNTAX

```powershell
Confirm-ESXiCertificateInstalled [-server] <String> [-user] <String> [-pass] <String> [-esxiFqdn] <String>
 [-signedCertificate] <String> [<CommonParameters>]
```

## DESCRIPTION

The Confirm-ESXiCertificateInstalled cmdlet will get the thumbprint from the provided signed certificate and matches it with the certificate thumbprint from ESXi host.
You need to pass in the complete path for the certificate file.
Returns true if certificate is already installed, else returns false.

## EXAMPLES

### EXAMPLE 1

```powershell
Confirm-ESXiCertificateInstalled -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-w01-esx01.sfo.rainpole.io -signedCertificate F:\certificates\sfo01-w01-esx01.sfo.rainpole.io.cer
```

This example checks the thumbprint of the provided signed certificate with the thumbprint on ESXi host.

## PARAMETERS

### -server

The FQDN of the SDDC Manager.

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

The username to authenticate to SDDC Manager.

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

The password to authenticate to SDDC Manager.

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

### -esxiFqdn

The FQDN of the ESXi host to verify the certificate thumbprint against.

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

### -signedCertificate

The complete path for the signed certificate file.

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
