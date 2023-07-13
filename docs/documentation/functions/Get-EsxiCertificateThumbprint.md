# Get-EsxiCertificateThumbprint

## Synopsis

Retrieves an ESXi host's certificate thumbprint.

## Syntax

```powershell
Get-EsxiCertificateThumbprint [-server] <String> [-user] <String> [-pass] <String> [-esxiFqdn] <String> [<CommonParameters>]
```

## Description

The `Get-EsxiCertificateThumbprint` cmdlet retrieves an ESXi host's certificate thumbprint.

## Examples

### Example 1

```powershell
Get-EsxiCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
```

This example retrieves the ESXi host's certificate thumbprint for an ESXi host with the FQDN of sfo01-m01-esx01.sfo.rainpole.io.

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

### -esxiFqdn

The FQDN of the ESXi host to retrieve the certificate thumbprint.

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
