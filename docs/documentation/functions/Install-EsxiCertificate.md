# Install-EsxiCertificate

## SYNOPSIS

Install a certificate for an ESXi host or for each ESXi host in a cluster.

## SYNTAX

### cluster

```powershell
Install-EsxiCertificate [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String>
 [-certificateDirectory] <String> [-certificateFileExt] <String> [[-timeout] <String>] [<CommonParameters>]
```

### host

```powershell
Install-EsxiCertificate [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-esxiFqdn] <String>
 [-certificateDirectory] <String> [-certificateFileExt] <String> [[-timeout] <String>] [<CommonParameters>]
```

## DESCRIPTION

The Install-EsxiCertificate cmdlet will replace the certificate for an ESXi host or for each ESXi host in a cluster.
You must provide the directory containing the signed certificate files.
Certificate names should be in format \<FQDN\>.crt e.g.
sfo01-m01-esx01.sfo.rainpole.io.crt.
The workflow will put the ESXi host in maintenance mode with full data migration,
disconnect the ESXi host from the vCenter Server, replace the certificate, restart the ESXi host,
and the exit maintenance mode once the ESXi host is online.

## EXAMPLES

### EXAMPLE 1

```powershell
Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -certificateDirectory F:\certificates -certificateFileExt ".cer"
```

This example will install the certificate to the ESXi host sfo01-m01-esx01.sfo.rainpole.io in domain sfo-m01 from the provided path.

### EXAMPLE 2

```powershell
Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user <administrator@vsphere.local> -pass VMw@re1!
-domain sfo-m01 -cluster sfo-m01-cl01 -certificateDirectory F:\certificates -certificateFileExt ".cer"
```

This example will install certificates for each ESXi host in cluster sfo-m01-cl01 in workload domain sfo-m01 from the provided path.

## PARAMETERS

### -server

The FQDN of the SDDC Manager.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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
Position: Named
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
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -domain

The name of the workload domain in which the ESXi host is located.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -cluster

The name of the cluster in which the ESXi host is located.

```yaml
Type: String
Parameter Sets: cluster
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The FQDN of the ESXi host.

```yaml
Type: String
Parameter Sets: host
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certificateDirectory

The directory containing the signed certificate files.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -certificateFileExt

The file extension of the certificate files.
One of ".crt", ".cer", ".pem", ".p7b", or ".p7c".

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -timeout

The timeout in seconds for putting the ESXi host in maintenance mode.
Default is 18000 seconds (5 hours).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 18000
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
