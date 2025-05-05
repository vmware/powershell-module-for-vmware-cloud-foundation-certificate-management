# Restart-EsxiHost

## Synopsis

Restarts an ESX host and poll for connection availability.

## Syntax

```powershell
Restart-EsxiHost [-esxiFqdn] <String> [-user] <String> [-pass] <String> [[-poll] <Boolean>] [[-timeout] <String>] [[-pollInterval] <String>] [<CommonParameters>]
```

## Description

The `Restart-EsxiHost` cmdlet restarts an ESX host and polls for connection availability.

Timeout value is in seconds.

## Examples

### Example 1

```powershell
Restart-EsxiHost -esxiFqdn [esx_host_fqdn] -user [admin_username] -pass [admin_password] -poll $true -timeout 1800 -pollInterval 30
```

This example restarts an ESX host and polls the connection availability every 30 seconds. It will timeout after 1800 seconds.

## Parameters

### -esxiFqdn

The fully qualified domain name of the ESX host.

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

The username to authenticate to the ESX host.

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

The password to authenticate to the ESX host.

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

### -poll

Poll for connection availability after restarting the ESX host.
Default is true.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: True
Accept pipeline input: False
Accept wildcard characters: False
```

### -timeout

The timeout value in seconds.
Default is 1800 seconds.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 1800
Accept pipeline input: False
Accept wildcard characters: False
```

### -pollInterval

The poll interval in seconds.
Default is 30 seconds.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).