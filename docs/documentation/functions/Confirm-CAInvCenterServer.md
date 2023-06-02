# Confirm-CAInvCenterServer

## SYNOPSIS

Verify the root certificate thumbprint matches with one of the CA thumbprints from vCenter Server instance.

## SYNTAX

```powershell
Confirm-CAInvCenterServer [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-signedCertificate] <String> [[-issuer] <String>] [<CommonParameters>]
```

## DESCRIPTION

The Confirm-CAInvCenterServer cmdlet gets the thumbprint from the root certificate and matches it with the CA thumbprint from the vCenter Server instance.
You need to pass in the complete path for the certificate file.
Returns true if thumbprint matches, else returns false.

## EXAMPLES

### EXAMPLE 1

```powershell
Confirm-CAInvCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -issuer rainpole -signedCertificate F:\certificates\Root64.cer
```

This example matches the thumbprint of provided root certificate file with the thumbprints on the vCenter Server instance matching the issuer "rainpole".

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

### -domain

The name of the workload domain to retrieve the vCenter Server instance's certificate thumbprints from.

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

The complete path for the root certificate file.

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

### -issuer

The name of the issuer to match with the thumbprint.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
