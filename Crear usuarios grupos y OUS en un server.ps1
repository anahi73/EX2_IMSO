 #Importamos el directorio activo
 Import-Module ActiveDirectory
 #Variables
 $domainName="DC=tubos,DC=com"

 #creamos las OUS
 New-ADOrganizationalUnit -Name Direccion -path $domainName
 New-ADOrganizationalUnit -Name Administracion -path $domainName
 New-ADOrganizationalUnit -Name Comercial -path $domainName
 New-ADOrganizationalUnit -Name Produccion -path $domainName


 #creamos los grupos
 New-ADGroup -Name Direccion -Path "OU=Direccion,$domainName" -GroupScope Global
 New-ADGroup -Name Administracion -Path "OU=Administracion,$domainName" -GroupScope DomainLocal
 New-ADGroup -Name Comercial -Path "OU=Comercial,$domainName" -GroupScope DomainLocal
 New-ADGroup -Name Produccion -Path "OU=Produccion,$domainName" -GroupScope DomainLocal


 #creamos los usuarios direccion y añadimos a las ous creadas
 for ($i = 1; $i -le 3 ; $i++) {
        $departamento="dire"
        $nombreUsuario = "Usu$departamento$i"
        $password = ConvertTo-SecureString "Password0" -AsPlainText -Force

        New-ADUser -SamAccountName $nombreUsuario -UserPrincipalName "$nombreUsuario@$domainName" -Name $nombreUsuario -Enabled $true -PasswordNeverExpires $true -AccountPassword $password  -Path "OU=Direccion,$domainName"

        # Agregar usuarios al grupo correspondiente
        Add-ADGroupMember -Identity "Direccion" -Members $nombreUsuario
    }
#creamos los usuarios Administracion
 for ($i = 1; $i -le 10 ; $i++) {
        $departamento="admin"
        $nombreUsuario = "Usu$departamento$i"
        $password = ConvertTo-SecureString "Password0" -AsPlainText -Force

        New-ADUser -SamAccountName $nombreUsuario -UserPrincipalName "$nombreUsuario@$domainName" -Name $nombreUsuario -Enabled $true -PasswordNeverExpires $true -AccountPassword $password -Path "OU=Administracion,$domainName"

        # Agregar usuarios al grupo correspondiente
        Add-ADGroupMember -Identity "Administracion" -Members $nombreUsuario
    }
#creamos los usuarios Comercial
 for ($i = 1; $i -le 2 ; $i++) {
        $departamento="com"
        $nombreUsuario = "Usu$departamento$i"
        $password = ConvertTo-SecureString "Password0" -AsPlainText -Force

        New-ADUser -SamAccountName $nombreUsuario -UserPrincipalName "$nombreUsuario@$domainName" -Path "OU=Comercial,$domainName" -Name $nombreUsuario -Enabled $true -PasswordNeverExpires $true -AccountPassword $password

        # Agregar usuarios al grupo correspondiente
        Add-ADGroupMember -Identity "Comercial" -Members $nombreUsuario
    }
#creamos los usuarios produccion
 for ($i = 1; $i -le 40 ; $i++) {
        $departamento="prod"
        $nombreUsuario = "Usu$departamento$i"
        $password = ConvertTo-SecureString "Password0" -AsPlainText -Force

        New-ADUser -SamAccountName $nombreUsuario -UserPrincipalName "$nombreUsuario@$domainName" -Path "OU=Produccion,$domainName" -Name $nombreUsuario -Enabled $true -PasswordNeverExpires $true -AccountPassword $password

        # Agregar usuarios al grupo correspondiente
        Add-ADGroupMember -Identity "Produccion" -Members $nombreUsuario
    }