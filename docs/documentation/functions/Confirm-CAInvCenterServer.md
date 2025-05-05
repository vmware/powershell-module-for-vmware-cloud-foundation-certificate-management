# Confirm-CAInvCenterServer

## Synopsis

Verifies the root certificate thumbprint matches with one of the CA thumbprints from vCenter instance.

## Syntax

```powershell
Confirm-CAInvCenterServer [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-signedCertificate] <String> [[-issuer] <String>] [<CommonParameters>]
```

## Description

The `Confirm-CAInvCenterServer` cmdlet gets the thumbprint from the root certificate and matches it with the CA thumbprint from the vCenter instance.

You need to pass in the complete path for the certificate file.

Returns `true` if thumbprint matches, else returns `false`.

## Examples

### Example 1

```powershell
Confirm-CAInvCenterServer -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -issuer [issuer_name] -signedCertificate [full_certificate_file_path]
```

This example matches the thumbprint of provided root certificate file with the thumbprints on the vCenter instance matching the issuer.

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

### -domain

The name of the workload domain to retrieve the vCenter instance's certificate thumbprints from.

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
