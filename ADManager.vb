Imports ActiveDs
Imports System.Text
Imports System.Text.RegularExpressions
Imports System.DirectoryServices
Imports System.Globalization
Imports System.Threading
Imports System.IO
Imports System.Collections.Generic

Namespace ADHRIntegration

    Public Class ADManager
#Region "Test Code"
        <Flags()> _
        Public Enum AdsUserFlags

            Script = 1                  '// 0x1
            AccountDisabled = 2              '// 0x2
            HomeDirectoryRequired = 8          ' // 0x8 
            AccountLockedOut = 16             '// 0x10
            PasswordNotRequired = 32          ' // 0x20
            PasswordCannotChange = 64           '// 0x40
            EncryptedTextPasswordAllowed = 128 '     // 0x80
            TempDuplicateAccount = 256        '  // 0x100
            NormalAccount = 512              '// 0x200
            AccountDisabledNormal = 514              '// 0x202
            PasswordNotRequiredNormal = 544              '// 0x220
            AccountDisabledNormalPwdNotReq = 546              '// 0x222
            InterDomainTrustAccount = 2048       ' // 0x800
            WorkstationTrustAccount = 4096      '  // 0x1000
            ServerTrustAccount = 8192          ' // 0x2000
            PasswordDoesNotExpire = 65536      '   // 0x10000
            PasswordDoesNotExpireNormal = 66048      '   // 0x10200
            AccountDisabledNormalPwdDoesNotExpire = 66050      '   // 0x10202
            MnsLogonAccount = 131072           '// 0x20000
            SmartCardRequired = 262144          '// 0x40000
            TrustedForDelegation = 524288       '  // 0x80000
            AccountNotDelegated = 1048576      '   // 0x100000
            UseDesKeyOnly = 2097152           '// 0x200000
            DontRequirePreauth = 4194304         '// 0x400000
            PasswordExpired = 8388608           '// 0x800000
            TrustedToAuthenticateForDelegation = 16777216 '// 0x1000000
            NoAuthDataRequired = 33554432         '// 0x2000000
            PasswordNotExpireNormal = 4260352         '// 0x410200
        End Enum
#End Region
#Region "Variables and Properties"

        Private strEmpDefPassword As String
        Private strAdNewUserConnString As String
        Private strAdConnString, strAdBrazilConnString, strAdEUConnString, strAdJPConnString, strAdCNConnString As String
        Private strGlobalAdConnString As String
        Private strAdLoginID As String
        Private strAdPassword As String
        Private intADLoginIDLength As Integer
        Private strEmailDomain As String

        Private strNetLoginID As String
        Private strGUIDEmpAccount As String
        Private strEmpEmailID As String
        Dim intAdNewUserMaxDays As Integer
        Dim strSuperDN As String = String.Empty
        'nakki 7/24/07
        Private blnUpdateADContactNumbers As Boolean = False
        Private blnDeActivateADAccount As Boolean = False
        Dim blnCreateADAccount As Boolean = False


        Public ReadOnly Property CreateADAccount() As Boolean
            Get
                Return blnCreateADAccount
            End Get
        End Property
        Public ReadOnly Property DeActivateADAccount() As Boolean
            Get
                Return blnDeActivateADAccount
            End Get
        End Property


        Public ReadOnly Property UpdateADContactNumber() As Boolean
            Get
                Return blnUpdateADContactNumbers
            End Get
        End Property


        'Login ID
        Public Property NetworkLoginID() As String
            Get
                Return strNetLoginID
            End Get
            Set(ByVal Value As String)
                strNetLoginID = Value
            End Set
        End Property

        'EmailID
        Public Property EmpEmailID() As String
            Get
                Return strEmpEmailID
            End Get
            Set(ByVal Value As String)
                strEmpEmailID = Value
            End Set
        End Property

        'AD Account GUID
        Public Property ADAccountGUID() As String
            Get
                Return strGUIDEmpAccount
            End Get
            Set(ByVal Value As String)
                strGUIDEmpAccount = Value
            End Set
        End Property

        'Supervisor Distinguished Name
        Public Property SuperDN() As String
            Get
                Return strSuperDN
            End Get
            Set(ByVal Value As String)
                strSuperDN = Value
            End Set
        End Property
#End Region

#Region " Setup variables"

        'Read the variable values from Config file
        Public Sub SetUpVariables()
            strEmpDefPassword = Utility.getConfigValue("EmpDefaultPassword")
            strAdNewUserConnString = Utility.getConfigValue("ADNewUserConnString")
            strAdConnString = Utility.getConfigValue("ADConnString")
            strAdBrazilConnString = Utility.getConfigValue("ADBrazilConnString")
            strAdEUConnString = Utility.getConfigValue("ADEUConnString")
            strAdJPConnString = Utility.getConfigValue("ADJPConnString")
            strAdCNConnString = Utility.getConfigValue("ADCNConnString")
            strGlobalAdConnString = Utility.getConfigValue("GlobalADConnString")
            strAdLoginID = Utility.getConfigValue("ADLoginID")
            strAdPassword = Utility.getConfigValue("ADPassword")
            strEmailDomain = Utility.getConfigValue("EMailDomain")
            intADLoginIDLength = CType(Utility.getConfigValue("ADLoginIDLength"), Integer)
            intAdNewUserMaxDays = CType(Utility.getConfigValue("ADID_In_NewUsers_MaxDays"), Integer)

            blnUpdateADContactNumbers = CType(Utility.getConfigValue("EnableUpdatingADContactNumbers"), Boolean)
            blnDeActivateADAccount = CType(Utility.getConfigValue("EnableADAccountDeActivation"), Boolean)
            blnCreateADAccount = CType(Utility.getConfigValue("EnableADAccountCreation"), Boolean)

        End Sub
#End Region

#Region "Cleanup New Users OU - if account stays there for too many days"


        'Delete Active directory account, find by GUID.
        Public Function DeleteUnUsedADAccount() As String

            Dim strOctGUIDString As String
            Dim blnSuccess As Boolean = False, intResult As Integer, strMsgDetails As String = String.Empty

            Dim strExceptionMessage As String = String.Empty
            Dim objDirSearcher As DirectorySearcher
            Dim objDirEntry As DirectoryEntry
            Try
                objDirEntry = New DirectoryEntry(strAdNewUserConnString, strAdLoginID, strAdPassword)

                'Bind to the native AdsObject to force authentication
                Dim dateVar As Date = Date.Now().AddDays((-1) * intAdNewUserMaxDays)

                'Search in AD
                objDirSearcher = New DirectorySearcher
                With objDirSearcher
                    .SearchRoot = objDirEntry
                    .SearchScope = SearchScope.Subtree
                    .ReferralChasing = ReferralChasingOption.None
                    .Filter = String.Format("(&(objectCategory=person)(objectclass=user)(whenCreated<={0}))", Utility.ToADDateString(dateVar))
                End With
                Dim objSearchResults As SearchResultCollection, objEmpADEntry As DirectoryEntry
                objSearchResults = objDirSearcher.FindAll()

                For Each objSearchRow As SearchResult In objSearchResults
                    objEmpADEntry = objSearchRow.GetDirectoryEntry()
                    Dim strName As String = objEmpADEntry.Name 'Due to a bug in DirectoryEntry force a bind by calling the Name property
                    objEmpADEntry.DeleteTree()
                    objEmpADEntry.CommitChanges()
                Next
                blnSuccess = True

            Catch ex As Exception
                'SendErrorEmail("DeleteUnUsedADAccount", ex.Message)
                strExceptionMessage = ex.Message
            Finally
                objDirSearcher.Dispose()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "DeleteUnUsedADAccount: " & strExceptionMessage & ControlChars.NewLine
            End If
            DeleteUnUsedADAccount = strMsgDetails

        End Function


#End Region

#Region "De-Activate AD Account - Search by GUID"
        'Search Active directory by GUID for Network ID and email for the Account.
        Public Function DeActivateADAccountByGUID(ByVal strGUID As String, ByVal strEmpERID As String, _
                                        ByVal strEmpEEID As String) As String
            Dim blnSuccess As Boolean = False, strMsgDetails As String = String.Empty
            Dim strExceptionMessage As String = String.Empty

            Dim strOctGUIDString As String
            strNetLoginID = String.Empty
            strEmpEmailID = String.Empty
            strOctGUIDString = Utility.Guid2OctetString(strGUID)

            Dim objDirEntry As DirectoryEntry
            Dim objDirSearcher As DirectorySearcher

            Try
                objDirEntry = New DirectoryEntry(strAdConnString, strAdLoginID, strAdPassword)

                'Bind to the native AdsObject to force authentication
                Dim adsiObj As Object = objDirEntry.NativeObject

                'Search in AD
                objDirSearcher = New DirectorySearcher(objDirEntry)
                objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectGUID={0}))", strOctGUIDString)
                Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
                objSearchResults = objDirSearcher.FindOne()

                'If one entry found.
                If Not objSearchResults Is Nothing Then
                    objEmpADEntry = objSearchResults.GetDirectoryEntry()
                    ' Here is where we set the value to enable the account
                    Dim intUsrAcControl As Integer
                    intUsrAcControl = CType(objEmpADEntry.Properties("userAccountControl").Value, Integer)
                    objEmpADEntry.Properties("userAccountControl").Value = intUsrAcControl Or 2
                    objEmpADEntry.Properties("msExchHideFromAddressLists").Value = "TRUE"

                    objEmpADEntry.CommitChanges()
                    objEmpADEntry.Close()
                End If
                blnSuccess = True

            Catch ex As Exception
                'SendErrorEmail("DeActivateADAccountByGUID", ex.Message)
                strExceptionMessage = ex.Message
            Finally
                objDirSearcher.Dispose()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "DeActivateADAccountByGUID: Deactivating the Active Directory account failed:" & ControlChars.NewLine & _
                "Company:" & strEmpERID & ":EmployeeID:" & strEmpEEID & ":" & strExceptionMessage & ControlChars.NewLine
            End If

            DeActivateADAccountByGUID = strMsgDetails
        End Function

#End Region

#Region "Search AD by GUID"
        'Search Active directory by GUID for Network ID and email for the Account.
        Public Sub SearchADAccount(ByVal strGUID As String)

            Dim strOctGUIDString As String
            strNetLoginID = String.Empty
            strEmpEmailID = String.Empty
            strSuperDN = String.Empty

            strOctGUIDString = Utility.Guid2OctetString(strGUID)

            Dim objDirEntry As DirectoryEntry
            objDirEntry = New DirectoryEntry(strAdConnString)

            'Bind to the native AdsObject to force authentication
            Dim adsiObj As Object = objDirEntry.NativeObject

            'Search in AD
            Dim objDirSearcher As New DirectorySearcher(objDirEntry)
            objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectGUID={0}))", strOctGUIDString)
            Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
            objSearchResults = objDirSearcher.FindOne()

            'If one entry found.
            If Not objSearchResults Is Nothing Then
                objEmpADEntry = objSearchResults.GetDirectoryEntry()

                'TODO: Get the right Domain Name from AD Object.
                Dim strDomainNAme As String = CType(objEmpADEntry.Properties("domain").Value, String)
                If Not strDomainNAme Is Nothing Then
                    If strDomainNAme.Length = 0 Then strDomainNAme = "NA"
                Else
                    strDomainNAme = "NA"
                End If

                strNetLoginID = strDomainNAme & "\" & CType(objEmpADEntry.Properties("samAccountName").Value, String)
                strEmpEmailID = CType(objEmpADEntry.Properties("mail").Value, String)
                strSuperDN = CType(objEmpADEntry.Properties("distinguishedName").Value, String)
            End If

        End Sub

#End Region

#Region "Delete AD Account - Searching by GUID"

        'Delete Active directory account, find by GUID.
        Public Function DeleteADAccount(ByVal strGUID As String, ByVal strEmpERID As String, _
                                        ByVal strEmpEEID As String) As String

            Dim strOctGUIDString As String
            Dim blnSuccess As Boolean = False, intResult As Integer, strMsgDetails As String = String.Empty
            Dim strExceptionMessage As String = String.Empty
            Dim objDirSearcher As DirectorySearcher
            Dim objDirEntry As DirectoryEntry
            Try

                strOctGUIDString = Utility.Guid2OctetString(strGUID)

                objDirEntry = New DirectoryEntry(strAdNewUserConnString, strAdLoginID, strAdPassword)

                'Bind to the native AdsObject to force authentication
                Dim adsiObj As Object = objDirEntry.NativeObject

                'Search in AD
                objDirSearcher = New DirectorySearcher(objDirEntry)
                objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectGUID={0}))", strOctGUIDString)
                Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
                objSearchResults = objDirSearcher.FindOne()

                'If one entry found.
                If Not objSearchResults Is Nothing Then
                    objEmpADEntry = objSearchResults.GetDirectoryEntry()
                    objEmpADEntry.DeleteTree()
                End If
                blnSuccess = True
            Catch ex As Exception
                'SendErrorEmail("DeleteADAccount", ex.Message)
                strExceptionMessage = ex.Message
            Finally
                objDirSearcher.Dispose()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "DeleteADAccount: Company:" & strEmpERID & ":EmployeeID:" & strEmpEEID & ":" & strExceptionMessage & ControlChars.NewLine
            End If

            DeleteADAccount = strMsgDetails

        End Function


#End Region

#Region "Search AD by AD AccountID"
        'Search Active directory by AD AccountID for corresponding GUID.
        Public Function getADAccountGUID(ByVal strNetLoginID As String) As String
            Dim strGUIDString As String = String.Empty

            Dim objDirEntry As DirectoryEntry
            objDirEntry = New DirectoryEntry(Me.strGlobalAdConnString)
            'objDirEntry = New DirectoryEntry(Me.strAdConnString)    ' strGlobalAdConnString)

            'Bind to the native AdsObject to force authentication
            Dim adsiObj As Object = objDirEntry.NativeObject

            'Search in AD
            Dim objDirSearcher As New DirectorySearcher(objDirEntry)
            objDirSearcher.Filter = String.Format("(&(objectclass=user)(samAccountName={0}))", strNetLoginID)
            Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
            objSearchResults = objDirSearcher.FindOne()

            'If one entry found.
            If Not objSearchResults Is Nothing Then
                objEmpADEntry = objSearchResults.GetDirectoryEntry()
                strGUIDString = objEmpADEntry.Guid.ToString
                strEmpEmailID = CType(objEmpADEntry.Properties("mail").Value, String)
                strSuperDN = CType(objEmpADEntry.Properties("distinguishedName").Value, String)
            End If

            getADAccountGUID = strGUIDString
        End Function
#End Region

#Region "Search AD New Users OU by Name"
        'Search Active directory by AD AccountID for corresponding GUID.
        Public Function IsNameExists(ByVal strLastName As String, ByVal strFirstName As String) As Boolean

            IsNameExists = False

            Dim objDirEntry As DirectoryEntry
            objDirEntry = New DirectoryEntry(strAdNewUserConnString)

            'Bind to the native AdsObject to force authentication
            Dim adsiObj As Object = objDirEntry.NativeObject

            'Search in AD
            Dim objDirSearcher As New DirectorySearcher(objDirEntry)
            objDirSearcher.Filter = String.Format("(&(objectclass=user)(CN={0}))", strLastName & ", " & strFirstName)
            Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
            objDirSearcher.SearchScope = SearchScope.Subtree

            objSearchResults = objDirSearcher.FindOne()

            'If one entry found.
            If Not objSearchResults Is Nothing Then
                IsNameExists = True
            End If

            objSearchResults = Nothing
            objDirSearcher.Dispose()
            objDirSearcher = Nothing
            objDirEntry = Nothing

        End Function
#End Region

#Region "Create Active Directory Account"

        Public Function insertADAccount(ByRef drEmpRow As DataRow, ByRef drLocationRow As DataRow) As String

            Dim curCulture As CultureInfo = Thread.CurrentThread.CurrentCulture
            'Create TextInfo object.
            Dim tInfo As TextInfo = curCulture.TextInfo()

            Dim sbOutput As New StringBuilder
            Dim strEmployer, strEmployeeNo, strFirstName, strLastName, strTitle, strWorkPhone, strWorkExtension, _
                strFaxNumber, strCellPhone, strPagerNumber, strDepartment, srLocation, _
                strEmpLoginID, strEmailID, strPcFirstName, strPcLastName, strCompany, strADCN_Name, _
                strLocName, strLocAddr1, strLocAddr2, strLocCity, strLocState, strLocZip, strLocCountry, _
                 strCommonName, strPcCommonName, strLocCountryAbrv As String
            Dim intADCountryCode As Integer = 0

            strLocName = String.Empty
            strLocAddr1 = String.Empty
            strLocAddr2 = String.Empty
            strLocCity = String.Empty
            strLocState = String.Empty
            strLocZip = String.Empty
            strLocCountry = String.Empty

            'Employee Office Location data
            If Not drLocationRow Is Nothing Then
                strLocName = drLocationRow.Item("Name").ToString
                strLocAddr1 = drLocationRow.Item("Address1").ToString
                strLocAddr2 = drLocationRow.Item("Address2").ToString
                strLocCity = drLocationRow.Item("City").ToString
                strLocState = drLocationRow.Item("State").ToString
                strLocZip = drLocationRow.Item("Zip").ToString
                strLocCountry = drLocationRow.Item("Country").ToString
                strLocCountryAbrv = drLocationRow.Item("ADCountryAbrv").ToString
                If Not (drLocationRow.Item("ADCountryCode") Is DBNull.Value) Then
                    intADCountryCode = CType(drLocationRow.Item("ADCountryCode"), Integer)
                End If
            End If

            'Read the supervisor GUID
            Dim strSupervisorADGUID As String = String.Empty
            Me.strSuperDN = String.Empty
            strSupervisorADGUID = drEmpRow.Item("SupervisorID").ToString.Trim
            'If Supervisor specified in Infinium, gt the DN from AD
            If strSupervisorADGUID.Length > 0 Then
                SearchADAccount(strSupervisorADGUID)
            End If

            strEmployer = drEmpRow.Item("ERPEmpERID").ToString
            If strEmployer = "TKS" Then
                strEmployer = "TKH"
            End If
            strEmployeeNo = drEmpRow.Item("ERPEmpEEID").ToString
            strFirstName = Trim(drEmpRow.Item("FirstName").ToString).ToLower
            strLastName = Trim(drEmpRow.Item("LastName").ToString).Replace(".", "").ToLower
            strCommonName = Trim(drEmpRow.Item("NickName").ToString)

            strTitle = drEmpRow.Item("Title").ToString
            strDepartment = drEmpRow.Item("Department").ToString
            srLocation = drEmpRow.Item("Location").ToString
            strCompany = drEmpRow.Item("Department").ToString

            'Contact numbers.
            strWorkPhone = drEmpRow.Item("WorkPhone").ToString.Trim
            strWorkPhone = Me.GetContactFormat(strWorkPhone, strLocCountryAbrv)

            strWorkExtension = drEmpRow.Item("WorkExtension").ToString.Trim
            If Trim(strWorkExtension).Length > 0 Then
                strWorkPhone = strWorkPhone & " Ext:" & Trim(strWorkExtension)
            End If

            strFaxNumber = drEmpRow.Item("Fax").ToString.Trim
            strFaxNumber = GetContactFormat(strFaxNumber, strLocCountryAbrv)
            'strCellPhone = drEmpRow.Item("CellPhone").ToString.Trim
            strPagerNumber = drEmpRow.Item("Pager").ToString.Trim
            strPagerNumber = GetContactFormat(strPagerNumber, strLocCountryAbrv)

            'Check special Chars and remove all but specified ones in config file.
            strFirstName = Me.GetCleanName(strFirstName)
            strLastName = Me.GetCleanName(strLastName)
            strCommonName = Me.GetCleanName(strCommonName)

            'Convert to proper case.
            strPcFirstName = Utility.ProperCelt(strFirstName)
            strPcLastName = Utility.ProperCelt(strLastName)
            strPcCommonName = Utility.ProperCelt(strCommonName)


            Dim blnSuccess As Boolean = False, intResult As Integer, strMsgDetails As String = String.Empty
            Dim strExceptionMessage As String = String.Empty
            Dim objUsers As DirectoryEntries
            Dim objDENewEmp As DirectoryEntry
            Dim AuthTypes As AuthenticationTypes  ' Authentication flags.
            Dim intPort As Integer, strPort As String
            Const ADS_OPTION_PASSWORD_PORTNUMBER As Long = 6
            Const ADS_OPTION_PASSWORD_METHOD As Long = 7

            Const ADS_PASSWORD_ENCODE_REQUIRE_SSL As Integer = 0
            Const ADS_PASSWORD_ENCODE_CLEAR As Integer = 1
            strPort = "389"

            'Get Unused Login ID for this Employee.
            strEmpLoginID = getNewADLoginID(strFirstName, strLastName)
            strEmailID = strEmpLoginID & strEmailDomain
            AuthTypes = AuthenticationTypes.SecureSocketsLayer Or AuthenticationTypes.Secure
            Dim objDE As DirectoryEntry
            Try

                If IsNameExists(strPcLastName, strPcFirstName) Then
                    strADCN_Name = strPcLastName & "\, " & strPcFirstName & "-" & strEmpLoginID
                Else
                    strADCN_Name = strPcLastName & "\, " & strPcFirstName
                End If

                objDE = New DirectoryEntry(strAdNewUserConnString, strAdLoginID, strAdPassword)
                objUsers = objDE.Children
                objDENewEmp = objUsers.Add("CN=" & strADCN_Name, "user")

                objDENewEmp.Properties("company").Add(strEmployer)
                If strDepartment.Length = 0 Then
                    strDepartment = "Not Available"
                End If
                objDENewEmp.Properties("department").Add(Utility.ProperCelt(strDepartment))
                objDENewEmp.Properties("employeeID").Add(strEmployeeNo)
                objDENewEmp.Properties("samAccountName").Add(strEmpLoginID)
                objDENewEmp.Properties("userPrincipalName").Add(strEmailID)
                objDENewEmp.Properties("mail").Add(strEmailID)
                'objDENewEmp.Properties("givenName").Add(strPcFirstName)
                objDENewEmp.Properties("givenName").Add(strPcCommonName)
                objDENewEmp.Properties("sn").Add(strPcLastName)
                'objDENewEmp.Properties("displayName").Add(strPcLastName + ", " + strPcFirstName)
                objDENewEmp.Properties("displayName").Add(strPcLastName + ", " + strPcCommonName)
                'objDENewEmp.Properties("description").Add(Utility.ProperCelt(strTitle))
                If strTitle.Length = 0 Then
                    strTitle = "Not Available"
                End If
                'nakki 2/16/09 Description is not updated by HRDW Refresh
                ' objDENewEmp.Properties("description").Add(strTitle)
                'objDENewEmp.Properties("title").Add(Utility.ProperCelt(strTitle))
                objDENewEmp.Properties("title").Add(strTitle)

                If strWorkPhone.Length > 0 Then
                    objDENewEmp.Properties("telephoneNumber").Add(strWorkPhone)
                End If

                If strFaxNumber.Length > 0 Then
                    objDENewEmp.Properties("facsimileTelephoneNumber").Add(strFaxNumber)
                End If

                'If strCellPhone.Length > 0 Then
                '    objDENewEmp.Properties("mobile").Add(strCellPhone)
                'End If

                If strPagerNumber.Length > 0 Then
                    objDENewEmp.Properties("pager").Add(strPagerNumber)
                End If

                If Not (Me.strSuperDN = String.Empty) Then
                    objDENewEmp.Properties("manager").Add(strSuperDN)
                End If

                '--------
                'Employee Office Location data
                '--------
                'Physical Office Name from Location update with the Address and other details
                If Not (strLocName.Trim.Length = 0) Then
                    objDENewEmp.Properties("physicalDeliveryOfficeName").Add(strLocName)
                End If
                If Not (strLocAddr1.Trim.Length = 0) Then
                    objDENewEmp.Properties("streetAddress").Add(strLocAddr1 & ControlChars.NewLine & strLocAddr2)
                End If
                If Not (strLocCity.Trim.Length = 0) Then
                    objDENewEmp.Properties("l").Add(strLocCity)
                End If
                If Not (strLocState.Trim.Length = 0) Then
                    objDENewEmp.Properties("st").Add(strLocState)
                End If
                If Not (strLocZip.Trim.Length = 0) Then
                    objDENewEmp.Properties("postalCode").Add(strLocZip)
                End If

                'Country Code is integer, dropdown choice in AD GUI, entered in Locations table.
                If Not (intADCountryCode = 0) Then
                    objDENewEmp.Properties("countryCode").Add(intADCountryCode)
                    objDENewEmp.Properties("co").Add(strLocCountry)
                    objDENewEmp.Properties("c").Add(strLocCountryAbrv)
                End If

                objDENewEmp.CommitChanges()

                objDENewEmp.AuthenticationType = AuthenticationTypes.Secure
                objDENewEmp.Invoke("SetPassword", New Object() {strEmpDefPassword})

                objDENewEmp.CommitChanges()

                strGUIDEmpAccount = objDENewEmp.Guid().ToString
                'TODO: Get the right Domain Name from AD Object.
                Dim strDomainNAme As String = CType(objDENewEmp.Properties("domain").Value, String)
                If Not strDomainNAme Is Nothing Then
                    If strDomainNAme.Length = 0 Then strDomainNAme = "NA"
                Else
                    strDomainNAme = "NA"
                End If

                objDENewEmp.Close()

                strNetLoginID = strDomainNAme & "\" & strEmpLoginID
                strEmpEmailID = strEmailID
                blnSuccess = True

            Catch ex As Exception
                'SendErrorEmail("InsertADAccount", ex.Message)
                strExceptionMessage = ex.Message
            Finally
                objDE.Close()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "InsertADAccount: Company:" & strEmployer & ":EmployeeID:" & strEmployeeNo & ":" & strExceptionMessage & ControlChars.NewLine
            End If

            insertADAccount = strMsgDetails
        End Function

#End Region

#Region "Update Active Directory Account for changes in HR Record"

        Public Function UpdateADAccount(ByVal strGUID As String, ByRef drEmpRow As DataRow, ByVal strERID As String, ByVal strEEID As String) As String

            Dim sbOutput As New StringBuilder
            Dim strEmployer, strEmployeeNo, strFirstName, strLastName, strTitle, strWorkPhone, strWorkExtension, strHomePhone, strCellPhone, strPagerNumber, _
             strDepartment, strPcFirstName, strPcLastName, strCompany, strFaxNumber, strCommonName, strPcCommonName As String
            'Dim strlocation As String
            Dim strLocName, strLocAddr1, strLocAddr2, strLocCity, strLocState, strLocZip, strLocCountry, strLocCountryAbrv As String
            Dim intADCountryCode As Integer = 0
            Dim strADNetLoginID As String = String.Empty
            Dim strADEmpEmailID As String = String.Empty
            Dim blnShowCellPhone, blnShowHomePhone As Boolean
            Dim blnIsUpdateMgrToADBlocked As Boolean

            Dim strSupervisorADGUID As String = String.Empty
            Me.strSuperDN = String.Empty
            Dim blnSuccess As Boolean = False, intResult As Integer, strMsgDetails As String = String.Empty
            Dim strExceptionMessage As String = String.Empty

            Dim objDirEntry As DirectoryEntry

            Try
                strSupervisorADGUID = drEmpRow.Item("SupervisorID").ToString.Trim
                blnIsUpdateMgrToADBlocked = CType(drEmpRow.Item("IsUpdateMgrToADBlocked"), Boolean)
                'If Supervisor specified in Infinium, and Okay to Update Mgr in AD, gt the DN from AD
                If (strSupervisorADGUID.Length > 0) And (Not blnIsUpdateMgrToADBlocked) Then
                    SearchADAccount(strSupervisorADGUID)
                End If

                'Employee Office Location data
                'If Not drLocationRow Is Nothing Then
                strLocName = drEmpRow.Item("Location").ToString
                strLocAddr1 = drEmpRow.Item("Address1").ToString
                strLocAddr2 = drEmpRow.Item("Address2").ToString
                strLocCity = drEmpRow.Item("City").ToString
                strLocState = drEmpRow.Item("State").ToString
                strLocZip = drEmpRow.Item("Zip").ToString
                strLocCountry = drEmpRow.Item("Country").ToString
                strLocCountryAbrv = drEmpRow.Item("ADCountryAbrv").ToString
                If Not (drEmpRow.Item("ADCountryCode") Is DBNull.Value) Then
                    intADCountryCode = CType(drEmpRow.Item("ADCountryCode"), Integer)
                End If
                'End If

                'Employee data
                strEmployer = drEmpRow.Item("ERPEmpERID").ToString
                If strEmployer = "TKS" Then
                    strEmployer = "TKH"
                End If
                strEmployeeNo = drEmpRow.Item("ERPEmpEEID").ToString
                strFirstName = Trim(drEmpRow.Item("FirstName").ToString)
                strLastName = Trim(drEmpRow.Item("LastName").ToString)
                strCommonName = Trim(drEmpRow.Item("NickName").ToString)

                strTitle = drEmpRow.Item("Title").ToString
                strDepartment = drEmpRow.Item("Department").ToString
                ' srLocation = drEmpRow.Item("Location").ToString
                strCompany = drEmpRow.Item("Department").ToString

                'Contact numbers
                strWorkPhone = drEmpRow.Item("WorkPhone").ToString.Trim
                strWorkPhone = GetContactFormat(strWorkPhone, strLocCountryAbrv)
                strWorkExtension = drEmpRow.Item("WorkExtension").ToString.Trim
                If Trim(strWorkExtension).Length > 0 Then
                    strWorkPhone = strWorkPhone & " Ext:" & strWorkExtension
                End If
                strFaxNumber = drEmpRow.Item("Fax").ToString.Trim
                strFaxNumber = GetContactFormat(strFaxNumber, strLocCountryAbrv)
                strPagerNumber = drEmpRow.Item("Pager").ToString.Trim
                strPagerNumber = GetContactFormat(strPagerNumber, strLocCountryAbrv)

                strHomePhone = drEmpRow.Item("HomePhone").ToString.Trim
                blnShowHomePhone = CType(drEmpRow.Item("ShowHomePhone"), Boolean)
                If blnShowHomePhone Then
                    strHomePhone = GetContactFormat(strHomePhone, strLocCountryAbrv)
                    If Trim(strHomePhone).Length = 0 Then strHomePhone = Nothing
                Else
                    strHomePhone = Nothing
                End If

                strCellPhone = drEmpRow.Item("CellPhone").ToString.Trim
                blnShowCellPhone = CType(drEmpRow.Item("ShowCellPhone"), Boolean)
                If blnShowCellPhone Then
                    strCellPhone = GetContactFormat(strCellPhone, strLocCountryAbrv)
                    If Trim(strCellPhone).Length = 0 Then strCellPhone = Nothing
                Else
                    strCellPhone = Nothing
                End If


                'Check special Chars and remove all but specified ones in config file.
                strFirstName = Me.GetCleanName(strFirstName)
                strLastName = Me.GetCleanName(strLastName)
                strCommonName = Me.GetCleanName(strCommonName)

                'Convert to proper case.
                strPcFirstName = Utility.ProperCelt(strFirstName)
                strPcLastName = Utility.ProperCelt(strLastName)
                strPcCommonName = Utility.ProperCelt(strCommonName)



                Dim strOctGUIDString As String
                strOctGUIDString = Utility.Guid2OctetString(strGUID)

                Dim objDirSearcher As DirectorySearcher
                Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry

                objDirEntry = New DirectoryEntry(strAdConnString, strAdLoginID, strAdPassword)

                'Search in AD
                objDirSearcher = New DirectorySearcher(objDirEntry)
                objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectGUID={0}))", strOctGUIDString)

                objSearchResults = objDirSearcher.FindOne()

                'If one entry found.
                If Not objSearchResults Is Nothing Then
                    objEmpADEntry = objSearchResults.GetDirectoryEntry()
                    '--------
                    'Employee data
                    '--------
                    If objEmpADEntry.Properties("company") Is Nothing Then
                        objEmpADEntry.Properties("company").Add(strEmployer)
                    Else
                        objEmpADEntry.Properties("company").Value = strEmployer
                    End If
                    If objEmpADEntry.Properties("department") Is Nothing Then
                        objEmpADEntry.Properties("department").Add(Utility.ProperCelt(strDepartment))
                    Else
                        objEmpADEntry.Properties("department").Value = Utility.ProperCelt(strDepartment)
                    End If
                    If objEmpADEntry.Properties("employeeID") Is Nothing Then
                        objEmpADEntry.Properties("employeeID").Add(strEmployeeNo)
                    Else
                        objEmpADEntry.Properties("employeeID").Value = strEmployeeNo
                    End If
                    'Self service form will take care of updating these fields
                    'If objEmpADEntry.Properties("displayName") Is Nothing Then
                    '    objEmpADEntry.Properties("displayName").Add(strPcLastName + ", " + strPcCommonName)
                    'Else
                    '    objEmpADEntry.Properties("displayName").Value = strPcLastName + ", " + strPcCommonName
                    'End If

                    'If objEmpADEntry.Properties("givenName") Is Nothing Then
                    '    'objEmpADEntry.Properties("givenName").Add(strPcFirstName)
                    '    objEmpADEntry.Properties("givenName").Add(strPcCommonName)
                    'Else
                    '    'objEmpADEntry.Properties("givenName").Value = strPcFirstName
                    '    objEmpADEntry.Properties("givenName").Value = strPcCommonName
                    'End If
                    'If objEmpADEntry.Properties("sn") Is Nothing Then
                    '    objEmpADEntry.Properties("sn").Add(strPcLastName)
                    'Else
                    '    objEmpADEntry.Properties("sn").Value = strPcLastName
                    'End If

                    'nakki 2/16/09 Description is not updated by HRDW Refresh
                    'If objEmpADEntry.Properties("description") Is Nothing Then
                    '    objEmpADEntry.Properties("description").Add(strTitle)
                    'Else
                    '    objEmpADEntry.Properties("description").Value = strTitle
                    'End If
                    If objEmpADEntry.Properties("title") Is Nothing Then
                        objEmpADEntry.Properties("title").Add(strTitle)
                    Else
                        objEmpADEntry.Properties("title").Value = strTitle
                    End If

                    'Nakki 7/24/2007 conditionally update the contact numbers. 
                    If UpdateADContactNumber Then
                        If Trim(strWorkPhone).Length = 0 Then
                            strWorkPhone = Nothing
                        End If
                        If objEmpADEntry.Properties("telephoneNumber") Is Nothing Then
                            objEmpADEntry.Properties("telephoneNumber").Add(strWorkPhone)
                        Else
                            objEmpADEntry.Properties("telephoneNumber").Value = strWorkPhone
                        End If

                        If objEmpADEntry.Properties("homePhone") Is Nothing Then
                            objEmpADEntry.Properties("homePhone").Add(strHomePhone)
                        Else
                            objEmpADEntry.Properties("homePhone").Value = strHomePhone
                        End If

                        'If strCellPhone.Length > 0 Then
                        If objEmpADEntry.Properties("mobile") Is Nothing Then
                            objEmpADEntry.Properties("mobile").Add(strCellPhone)
                        Else
                            objEmpADEntry.Properties("mobile").Value = strCellPhone
                        End If
                        'End If
                        If Trim(strPagerNumber).Length = 0 Then
                            strPagerNumber = Nothing
                        End If
                        If objEmpADEntry.Properties("pager") Is Nothing Then
                            objEmpADEntry.Properties("pager").Add(strPagerNumber)
                        Else
                            objEmpADEntry.Properties("pager").Value = strPagerNumber
                        End If

                        If Trim(strFaxNumber).Length = 0 Then
                            strFaxNumber = Nothing
                        End If
                        If objEmpADEntry.Properties("FacsimileTelephoneNumber") Is Nothing Then
                            objEmpADEntry.Properties("FacsimileTelephoneNumber").Add(strFaxNumber)
                        Else
                            objEmpADEntry.Properties("FacsimileTelephoneNumber").Value = strFaxNumber
                        End If

                    End If

                    If Not (Me.strSuperDN = String.Empty) Then
                        If objEmpADEntry.Properties("manager") Is Nothing Then
                            objEmpADEntry.Properties("manager").Add(strSuperDN)
                        Else
                            objEmpADEntry.Properties("manager").Value = strSuperDN
                        End If
                    End If
                    '--------
                    'Employee Office Location data
                    '--------
                    'Physical Office Name from Location update with the Address and other details
                    If Not (strLocName.Trim.Length = 0) Then
                        If objEmpADEntry.Properties("physicalDeliveryOfficeName") Is Nothing Then
                            objEmpADEntry.Properties("physicalDeliveryOfficeName").Add(strLocName)
                        Else
                            objEmpADEntry.Properties("physicalDeliveryOfficeName").Value = strLocName
                        End If
                    End If
                    If Not (strLocAddr1.Trim.Length = 0) Then
                        If objEmpADEntry.Properties("streetAddress") Is Nothing Then
                            objEmpADEntry.Properties("streetAddress").Add(strLocAddr1 & ControlChars.NewLine & strLocAddr2)
                        Else
                            objEmpADEntry.Properties("streetAddress").Value = strLocAddr1 & ControlChars.NewLine & strLocAddr2
                        End If
                    End If
                    If Not (strLocCity.Trim.Length = 0) Then
                        If objEmpADEntry.Properties("l") Is Nothing Then
                            objEmpADEntry.Properties("l").Add(strLocCity)
                        Else
                            objEmpADEntry.Properties("l").Value = strLocCity
                        End If
                    End If
                    If Not (strLocState.Trim.Length = 0) Then
                        If objEmpADEntry.Properties("st") Is Nothing Then
                            objEmpADEntry.Properties("st").Add(strLocState)
                        Else
                            objEmpADEntry.Properties("st").Value = strLocState
                        End If
                    End If
                    If Not (strLocZip.Trim.Length = 0) Then
                        If objEmpADEntry.Properties("postalCode") Is Nothing Then
                            objEmpADEntry.Properties("postalCode").Add(strLocZip)
                        Else
                            objEmpADEntry.Properties("postalCode").Value = strLocZip
                        End If
                    End If

                    'Country Code is integer, dropdown choice in AD GUI, entered in Locations table.
                    If Not (intADCountryCode = 0) Then
                        If objEmpADEntry.Properties("countryCode") Is Nothing Then
                            objEmpADEntry.Properties("countryCode").Add(intADCountryCode)
                        Else
                            objEmpADEntry.Properties("countryCode").Value = intADCountryCode
                        End If

                        If objEmpADEntry.Properties("co") Is Nothing Then
                            objEmpADEntry.Properties("co").Add(strLocCountry)
                        Else
                            objEmpADEntry.Properties("co").Value = strLocCountry
                        End If
                        If objEmpADEntry.Properties("c") Is Nothing Then
                            objEmpADEntry.Properties("c").Add(strLocCountryAbrv)
                        Else
                            objEmpADEntry.Properties("c").Value = strLocCountryAbrv
                        End If
                    End If
                    strADNetLoginID = "NA\" & CType(objEmpADEntry.Properties("samAccountName").Value, String)
                    If Not objEmpADEntry.Properties("mail") Is Nothing Then
                        strADEmpEmailID = CType(objEmpADEntry.Properties("mail").Value, String)
                    End If

                    objEmpADEntry.CommitChanges()

                    'Update the ADUserID and Email ID, so can be updated to EmpSelf Table in HRDW Later.
                    drEmpRow.Item("ADUserID") = strADNetLoginID
                    drEmpRow.Item("Email") = strADEmpEmailID
                    drEmpRow.AcceptChanges()

                Else
                    '5/18/2007 - nakki
                    'We are not interested in employees missing AD Account when updating the AD back
                    'The GUID is NOT necessarily from AD Account, in cases for emps with no AD Accounts.
                    'Throw New Exception("AD Account not found for Employee: Name= " & strPcLastName & "," & strPcFirstName)
                End If
                blnSuccess = True
            Catch ex As Exception
                strExceptionMessage = ex.Message
            Finally
                If Not (objDirEntry Is Nothing) Then objDirEntry.Close()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "UpdateADAccount: Company:" & strERID & ":EmployeeID:" & strEEID & ":" & strExceptionMessage & ControlChars.NewLine
            End If

            UpdateADAccount = strMsgDetails
        End Function
#End Region

#Region "Update AD Contact numbers"
        '-------------------------------------------------------------------------------------------
        'Updates the Workphone, Cellphone, Pager and Fax numbers for the employees in Infinium to the AD  
        '-------------------------------------------------------------------------------------------

        Public Function UpdateADContactNumbers(ByRef dsEmpRecords As DataSet) As String

            Dim blnSuccess As Boolean = False, intResult As Integer, strMsgDetails As String = String.Empty
            Dim strExceptionMessage As String = String.Empty
            Dim strGUID, strWorkPhone, strFaxNumber, strCellPhone, strPagerNumber, strEmployeeNo, strEmployer As String

            Dim strOctGUIDString As String
            Dim sbMessage As StringBuilder = New StringBuilder

            Dim objDirEntry As DirectoryEntry
            Dim objDirSearcher As DirectorySearcher
            Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
            If dsEmpRecords.Tables(0).Rows.Count > 0 Then

                Dim drEmpRow As DataRow
                For Each drEmpRow In dsEmpRecords.Tables(0).Rows

                    strGUID = drEmpRow.Item("EmpGUID").ToString.Trim
                    strOctGUIDString = Utility.Guid2OctetString(strGUID)

                    'Employee data
                    strEmployer = drEmpRow.Item("ERPEmpERID").ToString
                    strEmployeeNo = drEmpRow.Item("ERPEmpEEID").ToString

                    strWorkPhone = drEmpRow.Item("WorkPhone").ToString.Trim
                    strFaxNumber = drEmpRow.Item("Fax").ToString.Trim
                    strCellPhone = drEmpRow.Item("CellPhone").ToString.Trim
                    strPagerNumber = drEmpRow.Item("Pager").ToString.Trim

                    Try
                        objDirEntry = New DirectoryEntry(strAdConnString, strAdLoginID, strAdPassword)

                        'Search in AD
                        objDirSearcher = New DirectorySearcher(objDirEntry)
                        objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectGUID={0}))", strOctGUIDString)

                        objSearchResults = objDirSearcher.FindOne()

                        'If one entry found.
                        If Not objSearchResults Is Nothing Then
                            objEmpADEntry = objSearchResults.GetDirectoryEntry()
                            If strWorkPhone.Length > 0 Then
                                If objEmpADEntry.Properties("telephoneNumber") Is Nothing Then
                                    objEmpADEntry.Properties("telephoneNumber").Add(strWorkPhone)
                                Else
                                    objEmpADEntry.Properties("telephoneNumber").Value = strWorkPhone
                                End If
                            End If
                            If strCellPhone.Length > 0 Then
                                If objEmpADEntry.Properties("mobile") Is Nothing Then
                                    objEmpADEntry.Properties("mobile").Add(strCellPhone)
                                Else
                                    objEmpADEntry.Properties("mobile").Value = strCellPhone
                                End If
                            End If
                            If strPagerNumber.Length > 0 Then
                                If objEmpADEntry.Properties("pager") Is Nothing Then
                                    objEmpADEntry.Properties("pager").Add(strPagerNumber)
                                Else
                                    objEmpADEntry.Properties("pager").Value = strPagerNumber
                                End If
                            End If
                            If strFaxNumber.Length > 0 Then
                                If objEmpADEntry.Properties("FacsimileTelephoneNumber") Is Nothing Then
                                    objEmpADEntry.Properties("FacsimileTelephoneNumber").Add(strFaxNumber)
                                Else
                                    objEmpADEntry.Properties("FacsimileTelephoneNumber").Value = strFaxNumber
                                End If
                            End If

                            objEmpADEntry.CommitChanges()
                        End If
                    Catch ex As Exception
                        'SendErrorEmail("UpdateADAccount", ex.Message)
                        sbMessage.Append("Company:" & strEmployer & ":EmployeeID:" & strEmployeeNo & ":" & ex.Message & ControlChars.NewLine)
                    Finally
                        'objEmpADEntry.Close()
                        objDirEntry.Close()
                        'objDirEntry.Dispose()
                    End Try

                Next
            End If

            UpdateADContactNumbers = sbMessage.ToString

        End Function

#End Region

#Region "Check Active directory for available Auth USerID for use"

        Private Function getNewADLoginID(ByVal strFName As String, ByVal strLName As String) As String

            strFName = GetCleanString(strFName)
            strLName = GetCleanString(strLName)

            Dim strAdAccountID As String

            Dim intFNLength, intFNExtLength, intLNLength, intLNExtLength As Integer
            Dim intFNameSuffix As Integer = 1

            intFNLength = strFName.Length
            intFNExtLength = 1
            intLNLength = strLName.Length
            If intLNLength < intADLoginIDLength Then
                intLNExtLength = intLNLength
            Else
                intLNExtLength = intADLoginIDLength - 1
            End If


            Dim objDirEntryTemp As DirectoryEntry
            objDirEntryTemp = New DirectoryEntry(strAdConnString, strAdLoginID, strAdPassword)

            Dim objDirSearcher As New DirectorySearcher
            Dim objSearchResults As SearchResult

            objDirSearcher.SearchRoot = objDirEntryTemp
            objDirSearcher.SearchScope = SearchScope.Subtree
            objDirSearcher.PropertiesToLoad.Add("cn")
            Dim blnADIDCompleted As Boolean = False
            '
            'Too short first name could cause indexing error.
            'so added a "Counter" suffix to First name.
            Dim strFNameSufix As String = strFName
            Do Until blnADIDCompleted
                'Makeup the AccountID using the names and length constraints.
                strAdAccountID = strFNameSufix.Substring(0, intFNExtLength) & strLName.Substring(0, intLNExtLength)
                objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectcategory=Person)(SAMAccountName={0}))", strAdAccountID)
                objSearchResults = objDirSearcher.FindOne

                'If NO AD Account already exists with this UserID, thats the ID we are going to use.
                If objSearchResults Is Nothing Then
                    blnADIDCompleted = True
                Else
                    'Otherwise, using the combination of First & last name, form another UserID. 
                    blnADIDCompleted = False
                    If strFName.Length <= intFNExtLength Then
                        strFNameSufix = strFName & CType(intFNameSuffix, String)
                        intFNameSuffix = intFNameSuffix + 1
                        If strFName.Length = intFNExtLength Then
                            intFNExtLength = intFNExtLength + 1
                        End If
                    Else
                        intFNExtLength = intFNExtLength + 1
                    End If

                    If (intADLoginIDLength - intFNExtLength) < intLNExtLength Then
                        intLNExtLength = intLNExtLength - 1
                    End If

                End If

            Loop

            getNewADLoginID = strAdAccountID
        End Function
#End Region

#Region "AD Group Accounts - track changes"
        'Search Active directory by GUID for Network ID and email for the Account.
        Public Function GetADGroup() As String

            Dim strOctGUIDString As String
            Dim blnSuccess As Boolean = False, intResult As Integer, strMsgDetails As String = String.Empty

            Dim strExceptionMessage As String = String.Empty
            Dim objDirSearcher As DirectorySearcher
            Dim objDirEntry, objUserDirEntry As DirectoryEntry
            Try
                objDirEntry = New DirectoryEntry(Me.strAdConnString, strAdLoginID, strAdPassword)

                'Bind to the native AdsObject to force authentication
                Dim dateVar As Date = Date.Now().AddDays((-1))

                'Search in AD
                objDirSearcher = New DirectorySearcher
                With objDirSearcher
                    .SearchRoot = objDirEntry
                    .SearchScope = SearchScope.Subtree
                    .ReferralChasing = ReferralChasingOption.None
                    .Filter = String.Format("(&(objectCategory=Group)(objectclass=group)(whenChanged>={0}))", Utility.ToADDateString(dateVar))
                End With
                Dim objSearchResults As SearchResultCollection, objGroupADEntry As DirectoryEntry
                objSearchResults = objDirSearcher.FindAll()
                'Dim intPrimaryGroupID As Integer
                For Each objSearchRow As SearchResult In objSearchResults
                    objGroupADEntry = objSearchRow.GetDirectoryEntry()
                    Dim strName As String = objGroupADEntry.Name 'Due to a bug in DirectoryEntry force a bind by calling the Name property
                    'intPrimaryGroupID = CType(objEmpADEntry.Properties("primaryGroupID").Value, Integer)
                    ' arrMemberOf = objUser.GetEx("memberOf")
                    Dim strMembers As Object()
                    strMembers = CType(objGroupADEntry.Properties.Item("member").Value, Object())
                    'arrMemberOf = objUser.GetEx("member")

                    'objEmpADEntry.CommitChanges()
                    Dim strADPath As Object, sbStringBuilder As New StringBuilder
                    For Each strADPath In strMembers
                        objUserDirEntry = New DirectoryEntry("LDAP://" & strADPath.ToString)
                        sbStringBuilder.Append(objGroupADEntry.Guid.ToString & ":" & objUserDirEntry.Guid.ToString() & ControlChars.NewLine)
                    Next
                Next
                blnSuccess = True

            Catch ex As Exception
                'SendErrorEmail("GetADGroup", ex.Message)
                strExceptionMessage = ex.Message
            Finally
                objDirSearcher.Dispose()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "GetADGroup: " & strExceptionMessage & ControlChars.NewLine
            End If
            GetADGroup = strMsgDetails

        End Function
#End Region


#Region "Onetime use only: Clear EmployeeID in AD for Active Directory Only accounts"

        '        
        '        Public Function ClearADAAccounts(ByRef dsADOnlyUsers As DataSet) As String

        '            Dim strOctGUIDString, strWorkPhone, strWorkExtension As String
        '            Dim intResult As Integer, strMsgDetails As String = String.Empty
        '            Dim sbMessage As StringBuilder = New StringBuilder
        '            Dim strExceptionMessage As String = String.Empty
        '            Dim objDirSearcher As DirectorySearcher
        '            Dim objDirEntry As DirectoryEntry


        '            Dim dtADOnlyUsers As New DataTable, drRow As DataRow, objValue As Object
        '            Dim objSearchResults As SearchResultCollection
        '            Dim objEmpADEntry As DirectoryEntry
        '            Try

        '                objDirEntry = New DirectoryEntry(strAdConnString, strAdLoginID, strAdPassword)

        '                'Search in AD
        '                objDirSearcher = New DirectorySearcher
        '                With objDirSearcher
        '                    .SearchRoot = objDirEntry
        '                    .SearchScope = SearchScope.Subtree
        '                    .Filter = "(&(objectCategory=person)(objectclass=user)(company=ADA))"
        '                    .PageSize = 1000
        '                End With
        '                objDirSearcher.PropertiesToLoad.Add("employeeID")
        '                objDirSearcher.PropertiesToLoad.Add("objectGUID")
        '                objDirSearcher.PropertiesToLoad.Add("sAMAccountName")
        '                objDirSearcher.PropertiesToLoad.Add("sn")
        '                objDirSearcher.PropertiesToLoad.Add("displayName")
        '                objDirSearcher.PropertiesToLoad.Add("givenname")
        '                objDirSearcher.PropertiesToLoad.Add("cn")
        '                objDirSearcher.PropertiesToLoad.Add("company")

        '                'set perform the search
        '                objSearchResults = objDirSearcher.FindAll

        '                'Set table properties
        '                'BuildTableSchema(dtADOnlyUsers)
        '                'Dim strSamAccountID, strFirstName, strLastName, strMiddleInitials As String
        '                For Each objSearchRow As SearchResult In objSearchResults
        '                    'strSamAccountID = String.Empty
        '                    'strFirstName = String.Empty
        '                    'strLastName = String.Empty
        '                    'strMiddleInitials = String.Empty
        '                    'strWorkPhone = String.Empty
        '                    'strWorkExtension = String.Empty
        '                    Try

        '                        Dim strCompany As String = Nothing
        '                        If Not (objSearchRow.Properties("company") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("company").Item(0)
        '                            strCompany = Trim(objValue.ToString)
        '                            If strCompany = "ADA" Then
        '                                'Creat a new row
        '                                'drRow = dtADOnlyUsers.NewRow
        '                                ''AD Account
        '                                'If Not (objSearchRow.Properties("sAMAccountName") Is Nothing) Then
        '                                '    objValue = objSearchRow.Properties("sAMAccountName").Item(0)
        '                                '    drRow("ERPEmpEEID") = "NA\" & objValue.ToString()
        '                                '    strSamAccountID = objValue.ToString
        '                                'End If

        '                                ''Last Name
        '                                'drRow("LastName") = ""
        '                                'If Not (objSearchRow.Properties("sn") Is Nothing) Then
        '                                '    objValue = objSearchRow.Properties("sn").Item(0)
        '                                '    drRow("LastName") = objValue.ToString()
        '                                '    strLastName = objValue.ToString()
        '                                'End If

        '                                'drRow("FirstName") = ""
        '                                ''First Name
        '                                'If Not (objSearchRow.Properties("givenname") Is Nothing) Then
        '                                '    objValue = objSearchRow.Properties("givenname").Item(0)
        '                                '    drRow("FirstName") = objValue.ToString()
        '                                '    strFirstName = objValue.ToString()
        '                                'End If

        '                                'Guid
        '                                If Not (objSearchRow.Properties("objectGUID") Is Nothing) Then
        '                                    objEmpADEntry = objSearchRow.GetDirectoryEntry()

        '                                    objEmpADEntry.Properties("company").Value = "   "
        '                                    If Not (objSearchRow.Properties("employeeID") Is Nothing) Then
        '                                        objEmpADEntry.Properties("employeeID").Value = Nothing
        '                                    End If
        '                                    objEmpADEntry.CommitChanges()
        '                                End If

        '                                'Append row to table
        '                                'dtADOnlyUsers.Rows.Add(drRow)

        '                            End If
        '                        End If
        '                    Catch ex As Exception
        '                        'SendErrorEmail("GetADOnlyAccounts", ex.Message)
        '                        sbMessage.Append("Error in function ClearADAAccounts" & ex.Message & ControlChars.NewLine)

        '                    End Try
        '                Next
        '            Catch ex As Exception
        '                'SendErrorEmail("GetADOnlyAccounts", ex.Message)
        '                sbMessage.Append("Error in function ClearADAAccounts" & ex.Message & ControlChars.NewLine)

        '            End Try
        '            'Send the email message if there are errors.
        '            If sbMessage.Length > 0 Then
        '                strMsgDetails = "ClearADAAccounts: " & sbMessage.ToString & ControlChars.NewLine
        '            End If

        '            ClearADAAccounts = strMsgDetails

        '        End Function

#End Region

#Region "Return list of Active Directory Only accounts"


        'Get Active directory only account.
        Public Function GetADOnlyAccounts(ByRef dsADOnlyUsers As DataSet) As String

            Dim strOctGUIDString, strWorkPhone, strWorkExtension As String
            Dim intResult As Integer, strMsgDetails As String = String.Empty
            Dim sbMessage As StringBuilder = New StringBuilder
            Dim strExceptionMessage As String = String.Empty
            Dim objDirSearcher As DirectorySearcher
            Dim objDirEntry As DirectoryEntry


            Dim dtADOnlyUsers As New DataTable, drRow As DataRow, objValue As Object
            Dim objSearchResults As SearchResultCollection
            Dim objEmpADEntry As DirectoryEntry

            Dim connectStrings As List(Of String) = GetADConnectStrings()
            Dim regionConnectionString As String


            dtADOnlyUsers = New DataTable
            BuildTableSchema(dtADOnlyUsers)
            For Each regionConnectionString In connectStrings
                Try

                    'objDirEntry = New DirectoryEntry(strGlobalAdConnString, strAdLoginID, strAdPassword)
                    objDirEntry = New DirectoryEntry(regionConnectionString, strAdLoginID, strAdPassword)
                    'TODO:Following used for test only - delete it later
                    'objDirEntry = New DirectoryEntry(strAdNewUserConnString, strAdLoginID, strAdPassword)

                    'Search in AD
                    objDirSearcher = New DirectorySearcher
                    With objDirSearcher
                        .SearchRoot = objDirEntry
                        .SearchScope = SearchScope.Subtree
                        '.ReferralChasing = ReferralChasingOption.None
                        '.Filter = "(&(objectCategory=person)(objectclass=user)(msExchHideFromAddressLists=false))"
                        .Filter = "(&(objectCategory=person)(objectclass=user))"
                        '.Filter = "(&(objectCategory=person)(objectclass=user)(cn=User5, Syntel))"
                        '.Filter = "(&(objectclass=user))"
                        '.SizeLimit = 1000
                        .PageSize = 1000
                    End With



                    'Dim intPropertyCount As Integer = 0
                    'Dim output As String
                    'Dim objSchema As DirectoryEntry
                    'objSchema = objDirEntry.SchemaEntry()
                    'For Each strAttribute As String In objDirEntry.Properties.PropertyNames
                    '    output = output + vbTab & strAttribute
                    '    intPropertyCount = intPropertyCount + 1
                    '    Dim objAttribute As PropertyValueCollection = objSchema.Properties(strAttribute)
                    '    output = output + " (Syntax: " & objAttribute.Syntax & ")"
                    '    If objAttribute.MultiValued Then
                    '        output = output + " Multivalued" & vbCrLf
                    '    Else
                    '        output = output + " Single-valued" & vbCrLf
                    '    End If
                    'Next

                    'End Test 3/26/2008 nakki
                    objDirSearcher.PropertiesToLoad.Add("employeeID")
                    objDirSearcher.PropertiesToLoad.Add("objectGUID")
                    objDirSearcher.PropertiesToLoad.Add("manager")
                    objDirSearcher.PropertiesToLoad.Add("sAMAccountName")
                    objDirSearcher.PropertiesToLoad.Add("physicalDeliveryOfficeName") ' Office Name
                    objDirSearcher.PropertiesToLoad.Add("sn")
                    objDirSearcher.PropertiesToLoad.Add("displayName")
                    objDirSearcher.PropertiesToLoad.Add("givenname")
                    objDirSearcher.PropertiesToLoad.Add("cn")
                    objDirSearcher.PropertiesToLoad.Add("distinguishedName")
                    objDirSearcher.PropertiesToLoad.Add("initials")
                    objDirSearcher.PropertiesToLoad.Add("userAccountControl")
                    objDirSearcher.PropertiesToLoad.Add("title")
                    objDirSearcher.PropertiesToLoad.Add("department")
                    objDirSearcher.PropertiesToLoad.Add("telephoneNumber")
                    objDirSearcher.PropertiesToLoad.Add("mobile")
                    objDirSearcher.PropertiesToLoad.Add("homePhone")
                    objDirSearcher.PropertiesToLoad.Add("mail")
                    objDirSearcher.PropertiesToLoad.Add("facsimileTelephoneNumber")
                    objDirSearcher.PropertiesToLoad.Add("pager")
                    objDirSearcher.PropertiesToLoad.Add("streetAddress")
                    objDirSearcher.PropertiesToLoad.Add("l") 'City
                    objDirSearcher.PropertiesToLoad.Add("st")
                    objDirSearcher.PropertiesToLoad.Add("postalCode")
                    objDirSearcher.PropertiesToLoad.Add("co")
                    objDirSearcher.PropertiesToLoad.Add("msDS-UserAccountDisabled")
                    objDirSearcher.PropertiesToLoad.Add("msExchHideFromAddressLists")
                    objDirSearcher.PropertiesToLoad.Add("countryCode") ' Integer
                    objDirSearcher.PropertiesToLoad.Add("c") ' 2 char

                    'set perform the search
                    objSearchResults = objDirSearcher.FindAll
                    'Begin Test 3/26/2008 nakki
                    'For Each objSearchRow As SearchResult In objSearchResults

                    'result = resultCol[counter];
                    'result.Properties["givenName"][0]; 
                    'result.Properties["initials"][0];
                    'result.Properties["sn"][0]; 

                    'Next
                    ''Begin Test 3/26/2008 nakki
                    'Dim dsAttribute As New DataSet
                    'Dim dtADSchema As New DataTable
                    'With dtADSchema
                    '    .TableName = "ADSchemaAttributes"
                    '    .Columns.Add("Attribute", System.Type.GetType("System.String"))
                    '    .Columns.Add("Value", System.Type.GetType("System.String"))
                    'End With
                    'dsAttribute.Tables.Add(dtADSchema)
                    ''Dim objRootDSE As New DirectoryEntry("LDAP://RootDSE")

                    'Dim strAttrName As String
                    'Dim objValuex As Object
                    'For Each strAttrName In objSearchResults.PropertiesLoaded  'objDirEntry.Properties.PropertyNames
                    '    For Each objValuex In objDirEntry.Properties(strAttrName)
                    '        'Console.WriteLine(strAttrName & " : " & objValuex.ToString)
                    '        Dim dtAttRow As DataRow = dtADSchema.NewRow()
                    '        dtAttRow("Attribute") = strAttrName
                    '        dtAttRow("Value") = objValuex.ToString
                    '        dtADSchema.Rows.Add(dtAttRow)
                    '    Next objValuex
                    'Next strAttrName

                    'dsAttribute.WriteXml("C:/Intranet/TechHelp/Attributes.XML")
                    'dsAttribute = Nothing
                    'Set table properties

                    Dim strSamAccountID, strFirstName, strLastName, strMiddleInitials As String
                    For Each objSearchRow As SearchResult In objSearchResults
                        strSamAccountID = String.Empty
                        strFirstName = String.Empty
                        strLastName = String.Empty
                        strMiddleInitials = String.Empty
                        strWorkPhone = String.Empty
                        strWorkExtension = String.Empty
                        Try
                            'Employee ID is there for employees in Infinium HR Db
                            'For other AD only users, the property is Nothing. 
                            If (objSearchRow.Properties("employeeID") Is Nothing) OrElse (objSearchRow.Properties("employeeID").Count = 0) Then
                                Console.Out.WriteLine(objSearchRow.Properties("employeeID").ToString)


                                'Creat a new row
                                drRow = dtADOnlyUsers.NewRow
                                'AD Account
                                'If Not (objSearchRow.Properties("sAMAccountName") Is Nothing) Then
                                If Not (objSearchRow.Properties("sAMAccountName") Is Nothing) AndAlso (objSearchRow.Properties("sAMAccountName").Count > 0) Then
                                    objValue = objSearchRow.Properties("sAMAccountName").Item(0)
                                    strSamAccountID = objValue.ToString
                                    drRow("ERPEmpEEID") = GetNetBIOSName(objSearchRow.Properties("distinguishedName").Item(0))
                                End If
                                If Trim(strSamAccountID) = "DSumida" Then
                                    Dim strMyUserID As String = strSamAccountID
                                End If
                                'Last Name
                                drRow("LastName") = ""
                                If Not (objSearchRow.Properties("sn") Is Nothing) AndAlso (objSearchRow.Properties("sn").Count > 0) Then
                                    objValue = objSearchRow.Properties("sn").Item(0)
                                    drRow("LastName") = objValue.ToString()
                                    strLastName = objValue.ToString()
                                End If

                                drRow("FirstName") = ""
                                'First Name
                                If Not (objSearchRow.Properties("givenname") Is Nothing) AndAlso (objSearchRow.Properties("givenname").Count > 0) Then
                                    objValue = objSearchRow.Properties("givenname").Item(0)
                                    drRow("FirstName") = objValue.ToString()
                                    strFirstName = objValue.ToString()
                                End If

                                drRow("MiddleName") = ""
                                'First Name
                                If Not (objSearchRow.Properties("initials") Is Nothing) AndAlso (objSearchRow.Properties("initials").Count > 0) Then
                                    objValue = objSearchRow.Properties("initials").Item(0)
                                    drRow("MiddleName") = objValue.ToString()
                                    strMiddleInitials = objValue.ToString()
                                End If

                                If Trim(drRow("LastName").ToString()).Length > 0 Or Trim(drRow("FirstName").ToString()).Length > 0 Then

                                    'Guid
                                    If Not (objSearchRow.Properties("objectGUID") Is Nothing) AndAlso (objSearchRow.Properties("objectGUID").Count > 0) Then
                                        objEmpADEntry = objSearchRow.GetDirectoryEntry()
                                        'strGUIDString = objEmpADEntry.Guid.ToString
                                        'objValue = objSearchRow.Properties("objectGUID").Item(0)
                                        'drRow("EmployeeID") = CType(objValue, Guid).ToString
                                        drRow("EmployeeID") = objEmpADEntry.Guid.ToString
                                        'If objEmpADEntry.Properties("AccountDisabled"),   
                                        'drRow("Active") = "1"
                                        ' drRow("StatusID") = "CONTR"

                                    End If

                                    'Supervisor
                                    If Not (objSearchRow.Properties("manager") Is Nothing) AndAlso (objSearchRow.Properties("manager").Count > 0) Then
                                        objValue = objSearchRow.Properties("manager").Item(0)
                                        If CType(objValue, String).IndexOf("DC=NA") >= 0 Then
                                            drRow("SupervisorID") = Me.GetADGUIDByDN(objValue.ToString) 'objValue.ToString()
                                        End If
                                    End If
                                    'Employer=AD Account
                                    drRow("ERPEmpERID") = "ADA"



                                    'AD Location ID
                                    drRow("LocationID") = "ADLOC" 'objValue.ToString()

                                    'Physical Location description
                                    If Not (objSearchRow.Properties("physicalDeliveryOfficeName") Is Nothing) AndAlso (objSearchRow.Properties("physicalDeliveryOfficeName").Count > 0) Then
                                        objValue = objSearchRow.Properties("physicalDeliveryOfficeName").Item(0)
                                        drRow("Location") = objValue.ToString()
                                    End If

                                    'Last name
                                    'If Not (objSearchRow.Properties("sn") Is Nothing) Then
                                    '    objValue = objSearchRow.Properties("sn").Item(0)
                                    '    drRow("LastName") = objValue.ToString()
                                    'End If

                                    'Common Name
                                    If Not (objSearchRow.Properties("cn") Is Nothing) AndAlso (objSearchRow.Properties("cn").Count > 0) Then
                                        objValue = objSearchRow.Properties("cn").Item(0)
                                        Dim intstartPos As Integer = objValue.ToString().IndexOf(",")
                                        If intstartPos > 0 Then
                                            drRow("NickName") = objValue.ToString().Substring(intstartPos + 1)
                                        End If
                                    End If

                                    ''First Name
                                    'If Not (objSearchRow.Properties("givenname") Is Nothing) Then
                                    '    objValue = objSearchRow.Properties("givenname").Item(0)
                                    '    drRow("FirstName") = objValue.ToString()
                                    'End If

                                    drRow("Active") = "1"
                                    drRow("StatusID") = "CONTR"

                                    'Following are the Expiry statuses of four types of accounts.
                                    Dim MyUserFlags As AdsUserFlags = CType(objEmpADEntry.Properties("userAccountControl").Value, AdsUserFlags)
                                    If (MyUserFlags = AdsUserFlags.AccountDisabled Or MyUserFlags = AdsUserFlags.AccountDisabledNormal Or _
                                                MyUserFlags = AdsUserFlags.AccountDisabledNormalPwdNotReq Or MyUserFlags = AdsUserFlags.AccountDisabledNormalPwdDoesNotExpire) Then
                                        drRow("Active") = "0"
                                        drRow("StatusID") = "SEP"
                                    End If

                                    'Title
                                    If Not (objSearchRow.Properties("title") Is Nothing) AndAlso (objSearchRow.Properties("title").Count > 0) Then
                                        objValue = objSearchRow.Properties("title").Item(0)
                                        drRow("Title") = objValue.ToString()
                                    End If

                                    'Department
                                    If Not (objSearchRow.Properties("department") Is Nothing) AndAlso (objSearchRow.Properties("department").Count > 0) Then
                                        objValue = objSearchRow.Properties("department").Item(0)
                                        drRow("Department") = objValue.ToString()
                                    End If

                                    'Telephone 
                                    If Not (objSearchRow.Properties("telephoneNumber") Is Nothing) AndAlso (objSearchRow.Properties("telephoneNumber").Count > 0) Then
                                        objValue = objSearchRow.Properties("telephoneNumber").Item(0)
                                        strWorkPhone = objValue.ToString()
                                        If strWorkPhone.IndexOf("Ext:") <> -1 Then
                                            Dim intExtPos As Integer
                                            intExtPos = strWorkPhone.IndexOf("Ext:")
                                            If intExtPos = 0 Then
                                                strWorkPhone = ""
                                                strWorkExtension = strWorkPhone.Substring(4)
                                            Else
                                                strWorkExtension = strWorkPhone.Substring(intExtPos + 4)
                                                strWorkPhone = strWorkPhone.Substring(0, intExtPos - 1)
                                            End If
                                        Else
                                            strWorkExtension = ""
                                        End If

                                        drRow("WorkPhone") = Me.GetCleanString(strWorkPhone)
                                        drRow("WorkExtension") = GetCleanString(strWorkExtension)
                                    End If

                                    'Mobile
                                    If Not (objSearchRow.Properties("mobile") Is Nothing) AndAlso (objSearchRow.Properties("mobile").Count > 0) Then
                                        objValue = objSearchRow.Properties("mobile").Item(0)
                                        drRow("CellPhone") = Me.GetCleanString(objValue.ToString())
                                    End If

                                    'Homephone
                                    If Not (objSearchRow.Properties("homePhone") Is Nothing) AndAlso (objSearchRow.Properties("homePhone").Count > 0) Then
                                        objValue = objSearchRow.Properties("homePhone").Item(0)
                                        drRow("HomePhone") = Me.GetCleanString(objValue.ToString())
                                    End If

                                    'Email
                                    If Not (objSearchRow.Properties("mail") Is Nothing) AndAlso (objSearchRow.Properties("mail").Count > 0) Then
                                        objValue = objSearchRow.Properties("mail").Item(0)
                                        drRow("Email") = objValue.ToString()
                                    End If

                                    'Fax
                                    If Not (objSearchRow.Properties("facsimileTelephoneNumber") Is Nothing) AndAlso (objSearchRow.Properties("facsimileTelephoneNumber").Count > 0) Then
                                        objValue = objSearchRow.Properties("facsimileTelephoneNumber").Item(0)
                                        drRow("Fax") = Me.GetCleanString(objValue.ToString())
                                    End If

                                    'Pager
                                    If Not (objSearchRow.Properties("pager") Is Nothing) AndAlso (objSearchRow.Properties("pager").Count > 0) Then
                                        objValue = objSearchRow.Properties("pager").Item(0)
                                        drRow("Pager") = Me.GetCleanString(objValue.ToString())
                                    End If

                                    'Address
                                    If Not (objSearchRow.Properties("streetAddress") Is Nothing) AndAlso (objSearchRow.Properties("streetAddress").Count > 0) Then
                                        objValue = objSearchRow.Properties("streetAddress").Item(0)
                                        drRow("HomeAddress1") = objValue.ToString()
                                    End If

                                    'City
                                    If Not (objSearchRow.Properties("l") Is Nothing) AndAlso (objSearchRow.Properties("l").Count > 0) Then
                                        objValue = objSearchRow.Properties("l").Item(0)
                                        drRow("HomeCity") = objValue.ToString()
                                    End If

                                    'Street
                                    If Not (objSearchRow.Properties("st") Is Nothing) AndAlso (objSearchRow.Properties("st").Count > 0) Then
                                        objValue = objSearchRow.Properties("st").Item(0)
                                        drRow("HomeState") = objValue.ToString()
                                    End If

                                    'Postal Code
                                    If Not (objSearchRow.Properties("postalCode") Is Nothing) AndAlso (objSearchRow.Properties("postalCode").Count > 0) Then
                                        objValue = objSearchRow.Properties("postalCode").Item(0)
                                        drRow("HomeZip") = objValue.ToString()
                                    End If

                                    'Country
                                    If Not (objSearchRow.Properties("co") Is Nothing) AndAlso (objSearchRow.Properties("co").Count > 0) Then
                                        objValue = objSearchRow.Properties("co").Item(0)
                                        drRow("HomeCountry") = objValue.ToString()
                                    End If

                                    'Hide from Global Address Book
                                    If Not IsNothing(objSearchRow.Properties("msExchHideFromAddressLists")) AndAlso (objSearchRow.Properties("msExchHideFromAddressLists").Count > 0) Then
                                        drRow("HideFromAddressBook") = objSearchRow.Properties("msExchHideFromAddressLists").Item(0)
                                    End If

                                    drRow("ERPSource") = "3"

                                    'Country Code
                                    If Not (objSearchRow.Properties("countryCode") Is Nothing) AndAlso (objSearchRow.Properties("countryCode").Count > 0) Then
                                        objValue = objSearchRow.Properties("countryCode").Item(0)
                                        drRow("CountryCode") = objValue.ToString()
                                    End If

                                    'Country Abrv
                                    If Not (objSearchRow.Properties("c") Is Nothing) AndAlso (objSearchRow.Properties("c").Count > 0) Then
                                        objValue = objSearchRow.Properties("c").Item(0)
                                        drRow("CountryAbrv") = objValue.ToString()
                                    End If

                                    'Append row to table
                                    dtADOnlyUsers.Rows.Add(drRow)

                                End If

                            End If
                        Catch ex As Exception
                            'SendErrorEmail("GetADOnlyAccounts", ex.Message)
                            sbMessage.Append("NetworkID= " & strSamAccountID & ": Name= " & strLastName & ", " & strFirstName & ex.Message & ControlChars.NewLine)
                        End Try
                    Next


                Catch ex As Exception
                    'SendErrorEmail("GetADOnlyAccounts", ex.Message)
                    sbMessage.Append(ex.Message & ControlChars.NewLine)
                Finally
                    objDirSearcher.Dispose()
                End Try


            Next
            'Append table to dataset
            dsADOnlyUsers.Tables.Add(dtADOnlyUsers)

            'Send the email message if there are errors.
            If sbMessage.Length > 0 Then
                strMsgDetails = "GetADOnlyAccounts: " & sbMessage.ToString & ControlChars.NewLine
            End If
            GetADOnlyAccounts = strMsgDetails

        End Function

        Private Sub BuildTableSchema(ByRef dtADOnlyUsers As DataTable)

            With dtADOnlyUsers
                .TableName = "ADOnlyUsers"
                .Columns.Add("EmployeeID", System.Type.GetType("System.String"))
                .Columns.Add("SupervisorID", System.Type.GetType("System.String"))
                .Columns.Add("AltSuperID", System.Type.GetType("System.String"))
                .Columns.Add("ERPEmpERID", System.Type.GetType("System.String"))
                .Columns.Add("ERPEmpEEID", System.Type.GetType("System.String"))
                .Columns.Add("ERPCompany", System.Type.GetType("System.String"))
                .Columns.Add("Company_Abrv", System.Type.GetType("System.String"))
                .Columns.Add("EMDIVISION", System.Type.GetType("System.String"))
                .Columns.Add("LocationID", System.Type.GetType("System.String"))
                .Columns.Add("Location", System.Type.GetType("System.String"))
                .Columns.Add("Lastname", System.Type.GetType("System.String"))
                .Columns.Add("FirstNAme", System.Type.GetType("System.String"))
                .Columns.Add("MiddleName", System.Type.GetType("System.String"))
                .Columns.Add("NickName", System.Type.GetType("System.String"))
                .Columns.Add("Active", System.Type.GetType("System.String"))
                .Columns.Add("StatusID", System.Type.GetType("System.String"))
                .Columns.Add("HireDate", System.Type.GetType("System.String"))
                .Columns.Add("TermDate", System.Type.GetType("System.String"))
                .Columns.Add("PayType", System.Type.GetType("System.String"))
                .Columns.Add("Title", System.Type.GetType("System.String"))
                .Columns.Add("Department", System.Type.GetType("System.String"))
                .Columns.Add("OrgUnit", System.Type.GetType("System.String"))
                .Columns.Add("WorkPhone", System.Type.GetType("System.String"))
                .Columns.Add("WorkExtension", System.Type.GetType("System.String"))
                .Columns.Add("CellPhone", System.Type.GetType("System.String"))
                .Columns.Add("HomePhone", System.Type.GetType("System.String"))
                .Columns.Add("Pager", System.Type.GetType("System.String"))
                .Columns.Add("Fax", System.Type.GetType("System.String"))
                .Columns.Add("Email", System.Type.GetType("System.String"))
                .Columns.Add("DateOfBirth", System.Type.GetType("System.String"))
                .Columns.Add("MaritalStat", System.Type.GetType("System.String"))
                .Columns.Add("Sex", System.Type.GetType("System.String"))
                .Columns.Add("VacationAll", System.Type.GetType("System.String"))
                .Columns.Add("VacationTak", System.Type.GetType("System.String"))
                .Columns.Add("HomeAddress1", System.Type.GetType("System.String"))
                .Columns.Add("HomeAddress2", System.Type.GetType("System.String"))
                .Columns.Add("HomeCity", System.Type.GetType("System.String"))
                .Columns.Add("HomeState", System.Type.GetType("System.String"))
                .Columns.Add("HomeZip", System.Type.GetType("System.String"))
                .Columns.Add("HomeCountry", System.Type.GetType("System.String"))
                .Columns.Add("Emerg1Name", System.Type.GetType("System.String"))
                .Columns.Add("Emerg1Rel", System.Type.GetType("System.String"))
                .Columns.Add("Emerg1Phone", System.Type.GetType("System.String"))
                .Columns.Add("EmergencyContactCity", System.Type.GetType("System.String"))
                .Columns.Add("Emerg2Name", System.Type.GetType("System.String"))
                .Columns.Add("Emerg2Rel", System.Type.GetType("System.String"))
                .Columns.Add("Emerg2Phone", System.Type.GetType("System.String"))
                .Columns.Add("PassportNum", System.Type.GetType("System.String"))
                .Columns.Add("PassportExp", System.Type.GetType("System.String"))
                .Columns.Add("PassportCou", System.Type.GetType("System.String"))
                .Columns.Add("CountryOfCitizenship", System.Type.GetType("System.String"))
                .Columns.Add("AlienRegistrationNo", System.Type.GetType("System.String"))
                .Columns.Add("VisaNumber", System.Type.GetType("System.String"))
                .Columns.Add("VisaType", System.Type.GetType("System.String"))
                .Columns.Add("VisaExpDate", System.Type.GetType("System.String"))
                .Columns.Add("VisaIssuedCountry", System.Type.GetType("System.String"))
                .Columns.Add("HDayCalCode", System.Type.GetType("System.String"))
                .Columns.Add("ERPSource", System.Type.GetType("System.String"))
                .Columns.Add("HideFromAddressBook", System.Type.GetType("System.Boolean"))
                .Columns.Add("CountryCode", System.Type.GetType("System.String"))
                .Columns.Add("CountryAbrv", System.Type.GetType("System.String"))
            End With
        End Sub

        Private Function GetPDCServers() As Dictionary(Of String, String)
            Dim theForest As ActiveDirectory.Forest = ActiveDirectory.Forest.GetCurrentForest()
            Dim myDomains As ActiveDirectory.DomainCollection = theForest.Domains
            Dim domainName As String

            Dim firstPrefix As String
            Dim fullPrefix As String
            Dim TakataCorp_location, firstDot As Int16
            Dim domains As New Dictionary(Of String, String)
            Dim pdcName As String

            For Each myDomain As ActiveDirectory.Domain In myDomains
                domainName = myDomain.Name
                pdcName = myDomain.PdcRoleOwner.Name
                TakataCorp_location = domainName.IndexOf("somecorp", 0, StringComparison.CurrentCultureIgnoreCase)
                ' If it is just "somecorp.com", then do not add that item to the list
                If TakataCorp_location > 1 Then
                    fullPrefix = Mid(domainName, 1, TakataCorp_location)
                    firstDot = fullPrefix.IndexOf(".")
                    If firstDot >= 0 Then
                        firstPrefix = Mid(fullPrefix, 1, firstDot)
                    Else
                        firstPrefix = fullPrefix
                    End If
                    domains.Add(firstPrefix, pdcName)
                End If

            Next

            Return domains
        End Function

        Private Function GetDistinguishedNames() As Dictionary(Of String, String)

            Dim sRootDomain As String
            Dim deRootDSE As System.DirectoryServices.DirectoryEntry
            Dim deSearchRoot As System.DirectoryServices.DirectoryEntry
            Dim dsFindDomains As System.DirectoryServices.DirectorySearcher
            Dim srcResults As System.DirectoryServices.SearchResultCollection
            Dim distinguishedNames As New Dictionary(Of String, String)

            deRootDSE = New System.DirectoryServices.DirectoryEntry("GC://RootDSE")
            sRootDomain = "GC://" + deRootDSE.Properties("rootDomainNamingContext").Value.ToString()

            deSearchRoot = New System.DirectoryServices.DirectoryEntry(sRootDomain)
            dsFindDomains = New System.DirectoryServices.DirectorySearcher(deSearchRoot)
            dsFindDomains.Filter = "(objectCategory=domainDNS)"
            dsFindDomains.SearchScope = System.DirectoryServices.SearchScope.Subtree

            srcResults = dsFindDomains.FindAll()
            For Each srDomain As System.DirectoryServices.SearchResult In srcResults
                distinguishedNames.Add(srDomain.Properties("name")(0).ToString(), srDomain.Properties("distinguishedName")(0).ToString())
            Next

            Return distinguishedNames
        End Function

        Private Function GetADConnectStrings() As List(Of String)
            Dim PDCServers As Dictionary(Of String, String) = GetPDCServers()
            Dim DistNames As Dictionary(Of String, String) = GetDistinguishedNames()
            Dim connectString, region, distinguishedName As String
            Dim connStrings As New List(Of String)


            distinguishedName = ""

            For Each pair As KeyValuePair(Of String, String) In PDCServers
                region = pair.Key
                If DistNames.TryGetValue(region, distinguishedName) Then
                    connectString = "LDAP://" + pair.Value + "/" + distinguishedName
                    connStrings.Add(connectString)
                End If

            Next

            Return connStrings
        End Function

#End Region

#Region "Update Active Directory Thumbnail pictures"

        Public Function UpdateADThumpPicture(ByVal strGUID As String, ByVal strFilePath As String) As String

            Dim blnSuccess As Boolean = False
            Dim strMsgDetails As String = String.Empty
            Dim strExceptionMessage As String = String.Empty
            Dim strADWorkConnString As String
            Dim strOctGUIDString As String
            Dim objDirEntry As DirectoryEntry = Nothing
            Dim objDirSearcher As DirectorySearcher = Nothing
            Dim objSearchResults As SearchResult = Nothing
            Dim objEmpADEntry As DirectoryEntry = Nothing

            Try
                If strFilePath.IndexOf("TPSA_") <> -1 Then
                    strADWorkConnString = strAdBrazilConnString
                Else
                    strADWorkConnString = strAdConnString
                End If

                strOctGUIDString = Utility.Guid2OctetString(strGUID)
                objDirEntry = New DirectoryEntry(strADWorkConnString, strAdLoginID, strAdPassword)
                'Search in AD by GUID
                objDirSearcher = New DirectorySearcher(objDirEntry)
                objDirSearcher.Filter = String.Format("(&(objectclass=user)(objectGUID={0}))", strOctGUIDString)
                objSearchResults = objDirSearcher.FindOne()

                'If an entry found, update thumbnail picture
                If Not objSearchResults Is Nothing Then
                    objEmpADEntry = objSearchResults.GetDirectoryEntry()
                    If Not objEmpADEntry.Properties("thumbnailPhoto") Is Nothing Then
                        objEmpADEntry.Properties("thumbnailPhoto").Clear()
                    End If
                    objEmpADEntry.Properties("thumbnailPhoto").Add(ReadByteArray(strFilePath))
                    objEmpADEntry.CommitChanges()
                End If
                blnSuccess = True

            Catch ex As Exception
                strExceptionMessage = ex.Message
            Finally
                If Not (objDirEntry Is Nothing) Then objDirEntry.Close()
            End Try

            If Not blnSuccess Then
                strMsgDetails = "UpdateADThumpPicture: Universal GUID:" & strGUID & ":" & strExceptionMessage & ControlChars.NewLine
            End If

            UpdateADThumpPicture = strMsgDetails

        End Function

        Function ReadByteArray(ByVal strFileName)

            Dim fsInputFile As System.IO.FileStream = Nothing
            Dim binaryData() As Byte = Nothing
            Dim bytesRead As Long
            Try
                'Open file
                fsInputFile = New System.IO.FileStream(strFileName, System.IO.FileMode.Open, System.IO.FileAccess.Read)
                'Retrive Data into a byte array variable
                ReDim binaryData(fsInputFile.Length)
                bytesRead = fsInputFile.Read(binaryData, 0, CInt(fsInputFile.Length))

            Catch
                Throw
            Finally
                fsInputFile.Close()
            End Try
            ReadByteArray = binaryData

        End Function
#End Region

#Region "Return XReferenced employees from Active Directory"
        ' This function is to be used for dumping the AD Cross Referenced accounts into EmpSelf table with ADX as the ERPEmployerID"
        'Commented to avoid accidentally updating the HRDW_EmployeeSelf table. 
        'Public Function GetADXRefAccounts(ByRef dsADXRefUsers As DataSet) As String

        '    Dim strOctGUIDString As String
        '    Dim intResult As Integer, strMsgDetails As String = String.Empty
        '    Dim sbMessage As StringBuilder = New StringBuilder
        '    Dim strExceptionMessage As String = String.Empty
        '    Dim objDirSearcher As DirectorySearcher
        '    Dim objDirEntry As DirectoryEntry


        '    Dim dtADOnlyUsers As New DataTable, drRow As DataRow, objValue As Object
        '    Dim objSearchResults As SearchResultCollection
        '    Dim objEmpADEntry As DirectoryEntry
        '    Try

        '        objDirEntry = New DirectoryEntry(strAdConnString, strAdLoginID, strAdPassword)
        '        'TODO:Following used for test only - delete it later
        '        'objDirEntry = New DirectoryEntry(strAdNewUserConnString, strAdLoginID, strAdPassword)

        '        'Search in AD
        '        objDirSearcher = New DirectorySearcher
        '        With objDirSearcher
        '            .SearchRoot = objDirEntry
        '            .SearchScope = SearchScope.Subtree
        '            '.ReferralChasing = ReferralChasingOption.None
        '            '.Filter = "(&(objectCategory=person)(objectclass=user)(msExchHideFromAddressLists=false))"
        '            .Filter = "(&(objectCategory=person)(objectclass=user))"
        '            '.Filter = "(&(objectclass=user))"
        '            '.SizeLimit = 1000
        '            .PageSize = 1000
        '        End With
        '        objDirSearcher.PropertiesToLoad.Add("company")
        '        objDirSearcher.PropertiesToLoad.Add("employeeID")
        '        objDirSearcher.PropertiesToLoad.Add("objectGUID")
        '        objDirSearcher.PropertiesToLoad.Add("manager")
        '        objDirSearcher.PropertiesToLoad.Add("sAMAccountName")
        '        objDirSearcher.PropertiesToLoad.Add("physicalDeliveryOfficeName")
        '        objDirSearcher.PropertiesToLoad.Add("sn")
        '        objDirSearcher.PropertiesToLoad.Add("displayName")
        '        objDirSearcher.PropertiesToLoad.Add("givenname")
        '        objDirSearcher.PropertiesToLoad.Add("cn")
        '        objDirSearcher.PropertiesToLoad.Add("userAccountControl")
        '        objDirSearcher.PropertiesToLoad.Add("title")
        '        objDirSearcher.PropertiesToLoad.Add("department")
        '        objDirSearcher.PropertiesToLoad.Add("telephoneNumber")
        '        objDirSearcher.PropertiesToLoad.Add("mobile")
        '        objDirSearcher.PropertiesToLoad.Add("homePhone")
        '        objDirSearcher.PropertiesToLoad.Add("mail")
        '        objDirSearcher.PropertiesToLoad.Add("facsimileTelephoneNumber")
        '        objDirSearcher.PropertiesToLoad.Add("pager")
        '        objDirSearcher.PropertiesToLoad.Add("streetAddress")
        '        objDirSearcher.PropertiesToLoad.Add("l")
        '        objDirSearcher.PropertiesToLoad.Add("st")
        '        objDirSearcher.PropertiesToLoad.Add("postalCode")
        '        objDirSearcher.PropertiesToLoad.Add("co")
        '        objDirSearcher.PropertiesToLoad.Add("msDS-UserAccountDisabled")
        '        'set perform the search
        '        objSearchResults = objDirSearcher.FindAll

        '        'Set table properties
        '        BuildTableSchema(dtADOnlyUsers)
        '        Dim strSamAccountID, strFirstName, strLastName As String
        '        For Each objSearchRow As SearchResult In objSearchResults
        '            strSamAccountID = String.Empty
        '            strFirstName = String.Empty
        '            strLastName = String.Empty
        '            Try
        '                'Employee ID is there for employees in Infinium HR Db
        '                'For other AD only users, the property is Nothing. 
        '                If Not (objSearchRow.Properties("employeeID") Is Nothing) Then
        '                    'Creat a new row
        '                    drRow = dtADOnlyUsers.NewRow
        '                    'AD Account
        '                    If Not (objSearchRow.Properties("sAMAccountName") Is Nothing) Then
        '                        objValue = objSearchRow.Properties("sAMAccountName").Item(0)
        '                        'drRow("ERPEmpEEID") = "NA\" & objValue.ToString()
        '                        strSamAccountID = objValue.ToString
        '                    End If
        '                    objValue = objSearchRow.Properties("employeeID").Item(0)
        '                    drRow("ERPEmpEEID") = objValue.ToString

        '                    objValue = objSearchRow.Properties("company").Item(0)
        '                    drRow("ERPCompany") = objValue.ToString

        '                    'If Trim(strSamAccountID) = "Jtest" Then
        '                    '    Dim strMyUserID As String = strSamAccountID
        '                    'End If
        '                    'Last Name
        '                    drRow("LastName") = ""
        '                    If Not (objSearchRow.Properties("sn") Is Nothing) Then
        '                        objValue = objSearchRow.Properties("sn").Item(0)
        '                        drRow("LastName") = objValue.ToString()
        '                        strLastName = objValue.ToString()
        '                    End If

        '                    drRow("FirstName") = ""
        '                    'First Name
        '                    If Not (objSearchRow.Properties("givenname") Is Nothing) Then
        '                        objValue = objSearchRow.Properties("givenname").Item(0)
        '                        drRow("FirstName") = objValue.ToString()
        '                        strFirstName = objValue.ToString()
        '                    End If

        '                    If Trim(drRow("LastName").ToString()).Length > 0 Or Trim(drRow("FirstName").ToString()).Length > 0 Then

        '                        'Guid
        '                        If Not (objSearchRow.Properties("objectGUID") Is Nothing) Then
        '                            objEmpADEntry = objSearchRow.GetDirectoryEntry()
        '                            'strGUIDString = objEmpADEntry.Guid.ToString
        '                            'objValue = objSearchRow.Properties("objectGUID").Item(0)
        '                            'drRow("EmployeeID") = CType(objValue, Guid).ToString
        '                            drRow("EmployeeID") = objEmpADEntry.Guid.ToString
        '                            'If objEmpADEntry.Properties("AccountDisabled"),   
        '                            'drRow("Active") = "1"
        '                            ' drRow("StatusID") = "CONTR"

        '                        End If

        '                        'Supervisor
        '                        If Not (objSearchRow.Properties("manager") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("manager").Item(0)
        '                            If CType(objValue, String).IndexOf("DC=NA") >= 0 Then
        '                                drRow("SupervisorID") = Me.GetADGUIDByDN(objValue.ToString) 'objValue.ToString()
        '                            End If
        '                        End If
        '                        'Employer=AD Account
        '                        drRow("ERPEmpERID") = "ADX"

        '                        'AD Location ID
        '                        drRow("LocationID") = "ADLOC" 'objValue.ToString()

        '                        'Physical Location description
        '                        If Not (objSearchRow.Properties("physicalDeliveryOfficeName") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("physicalDeliveryOfficeName").Item(0)
        '                            drRow("Location") = objValue.ToString()
        '                        End If

        '                        'Last name
        '                        'If Not (objSearchRow.Properties("sn") Is Nothing) Then
        '                        '    objValue = objSearchRow.Properties("sn").Item(0)
        '                        '    drRow("LastName") = objValue.ToString()
        '                        'End If

        '                        'Common Name
        '                        If Not (objSearchRow.Properties("cn") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("cn").Item(0)
        '                            Dim intstartPos As Integer = objValue.ToString().IndexOf(",")
        '                            If intstartPos > 0 Then
        '                                drRow("NickName") = objValue.ToString().Substring(intstartPos + 1)
        '                            End If
        '                        End If

        '                        ''First Name
        '                        'If Not (objSearchRow.Properties("givenname") Is Nothing) Then
        '                        '    objValue = objSearchRow.Properties("givenname").Item(0)
        '                        '    drRow("FirstName") = objValue.ToString()
        '                        'End If

        '                        drRow("Active") = "1"
        '                        drRow("StatusID") = "CONTR"

        '                        'Following are the Expiry statuses of four types of accounts.
        '                        Dim MyUserFlags As AdsUserFlags = CType(objEmpADEntry.Properties("userAccountControl").Value, AdsUserFlags)
        '                        If (MyUserFlags = AdsUserFlags.AccountDisabled Or MyUserFlags = AdsUserFlags.AccountDisabledNormal Or _
        '                                    MyUserFlags = AdsUserFlags.AccountDisabledNormalPwdNotReq Or MyUserFlags = AdsUserFlags.AccountDisabledNormalPwdDoesNotExpire) Then
        '                            drRow("Active") = "0"
        '                            drRow("StatusID") = "SEP"
        '                        End If

        '                        'Title
        '                        If Not (objSearchRow.Properties("title") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("title").Item(0)
        '                            drRow("Title") = objValue.ToString()
        '                        End If

        '                        'Department
        '                        If Not (objSearchRow.Properties("department") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("department").Item(0)
        '                            drRow("Department") = objValue.ToString()
        '                        End If

        '                        'Telephone 
        '                        If Not (objSearchRow.Properties("telephoneNumber") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("telephoneNumber").Item(0)
        '                            drRow("WorkPhone") = objValue.ToString()
        '                        End If

        '                        'Mobile
        '                        If Not (objSearchRow.Properties("mobile") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("mobile").Item(0)
        '                            drRow("CellPhone") = objValue.ToString()
        '                        End If

        '                        'Homephone
        '                        If Not (objSearchRow.Properties("homePhone") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("homePhone").Item(0)
        '                            drRow("HomePhone") = objValue.ToString()
        '                        End If

        '                        'Email
        '                        If Not (objSearchRow.Properties("mail") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("mail").Item(0)
        '                            drRow("Email") = objValue.ToString()
        '                        End If

        '                        'Fax
        '                        If Not (objSearchRow.Properties("facsimileTelephoneNumber") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("facsimileTelephoneNumber").Item(0)
        '                            drRow("Fax") = objValue.ToString()
        '                        End If

        '                        'Pager
        '                        If Not (objSearchRow.Properties("pager") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("pager").Item(0)
        '                            drRow("Pager") = objValue.ToString()
        '                        End If

        '                        'Address
        '                        If Not (objSearchRow.Properties("streetAddress") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("streetAddress").Item(0)
        '                            drRow("HomeAddress1") = objValue.ToString()
        '                        End If

        '                        'City
        '                        If Not (objSearchRow.Properties("l") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("l").Item(0)
        '                            drRow("HomeCity") = objValue.ToString()
        '                        End If

        '                        'Street
        '                        If Not (objSearchRow.Properties("st") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("st").Item(0)
        '                            drRow("HomeState") = objValue.ToString()
        '                        End If

        '                        'Postal Code
        '                        If Not (objSearchRow.Properties("postalCode") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("postalCode").Item(0)
        '                            drRow("HomeZip") = objValue.ToString()
        '                        End If

        '                        'Country
        '                        If Not (objSearchRow.Properties("co") Is Nothing) Then
        '                            objValue = objSearchRow.Properties("co").Item(0)
        '                            drRow("HomeCountry") = objValue.ToString()
        '                        End If
        '                        drRow("ERPSource") = "3"

        '                        'Append row to table
        '                        dtADOnlyUsers.Rows.Add(drRow)

        '                    End If

        '                End If
        '            Catch ex As Exception
        '                'SendErrorEmail("GetADOnlyAccounts", ex.Message)
        '                sbMessage.Append("NetworkID= " & strSamAccountID & ": Name= " & strLastName & ", " & strFirstName & ex.Message & ControlChars.NewLine)
        '            End Try
        '        Next


        '    Catch ex As Exception
        '        'SendErrorEmail("GetADOnlyAccounts", ex.Message)
        '        sbMessage.Append(ex.Message & ControlChars.NewLine)
        '    Finally
        '        objDirSearcher.Dispose()
        '    End Try

        '    'Append table to dataset
        '    dsADXRefUsers.Tables.Add(dtADOnlyUsers)

        '    'Send the email message if there are errors.
        '    If sbMessage.Length > 0 Then
        '        strMsgDetails = "GetADOnlyAccounts: " & sbMessage.ToString & ControlChars.NewLine
        '    End If
        '    GetADXRefAccounts = strMsgDetails

        'End Function

#End Region

#Region "Search AD by DN"

        'Search Active directory by GUID for Network ID and email for the Account.
        Public Function GetADGUIDByDN(ByVal strDN As String) As String
            Dim strGUIDString As String = String.Empty
            If strDN.Trim.Length <> 0 Then
                'Dim objDirEntry As DirectoryEntry
                'objDirEntry = New DirectoryEntry(strAdConnString)

                ''Bind to the native AdsObject to force authentication
                'Dim adsiObj As Object = objDirEntry.NativeObject

                ''Search in AD
                'Dim objDirSearcher As New DirectorySearcher(objDirEntry)
                'objDirSearcher.Filter = "(&(objectclass=user)(" & strDN & "))"
                'Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
                'objSearchResults = objDirSearcher.FindOne()
                '------------------------
                'Try
                Dim objDirEntry As DirectoryEntry
                objDirEntry = New DirectoryEntry("GC://" & strDN)
                objDirEntry.Username = Me.strAdLoginID
                objDirEntry.Password = Me.strAdPassword
                'Bind to the native AdsObject to force authentication
                'Dim adsiObj As Object = objDirEntry.NativeObject

                'Search in AD
                Dim objDirSearcher As New DirectorySearcher(objDirEntry)
                'objDirSearcher.Filter = "(&(objectclass=user)(" & strDN & "))"
                Dim objSearchResults As SearchResult, objEmpADEntry As DirectoryEntry
                objSearchResults = objDirSearcher.FindOne()

                'If one entry found.
                If Not objSearchResults Is Nothing Then
                    objEmpADEntry = objSearchResults.GetDirectoryEntry()
                    strGUIDString = objEmpADEntry.Guid.ToString
                End If
                'Catch ex As Exception
                '    Throw ex
                'End Try
            End If
            GetADGUIDByDN = strGUIDString
        End Function

        'Retrieve the NETBIOS Name
        Private Function GetNetBIOSName(ByVal strFullName As String) As String
            'Declare local variables
            Dim objTrans As New NameTranslate
            Dim strDNSDomain As DirectoryEntry

            Try
                'Get the domain\username
                strDNSDomain = New DirectoryEntry(strGlobalAdConnString)
                objTrans = CreateObject("NameTranslate")
                objTrans.Init(3, strFullName)
                objTrans.Set(1, strFullName)
                Return objTrans.Get(3)
            Catch ex As Exception
                SendErrorEmail("GetNetBIOSName", "Input: " & strFullName & "Exception: " & ex.Message)
            Finally
                objTrans = Nothing
            End Try
        End Function

#End Region

#Region "Default Constructor"
        Public Sub New()
            SetUpVariables()
        End Sub
#End Region

#Region "Generic functions"

        Function GetCleanString(ByVal strIn As String) As String
            Dim strValue As String = String.Empty
            'CleanInput returns a string after stripping out all nonalphanumeric characters 
            ' Replace invalid characters with empty strings.
            GetCleanString = Regex.Replace(strIn, "[^\w]", "")
        End Function
        Public Function GetContactFormat(ByVal strIn As String, ByVal strCountryCode As String) As String
            Dim strValue As String = strIn
            If UCase(strCountryCode) = "MEX" Or UCase(strCountryCode) = "MX" Then
                If strIn.Length = 12 Then
                    strValue = String.Format("{0}-{1}-{2}-{3}", strIn.Substring(0, 2), strIn.Substring(2, 3), strIn.Substring(5, 3), strIn.Substring(8))
                End If
            Else
                If strIn.Length = 10 Then
                    strValue = String.Format("{0}-{1}-{2}", strIn.Substring(0, 3), strIn.Substring(3, 3), strIn.Substring(6))
                End If
            End If

            GetContactFormat = strValue
        End Function
        Function GetCleanName(ByVal strIn As String) As String
            'CleanInput returns a string after stripping out all nonalphanumeric characters 
            'except the characters specified in Config file.
            Dim strAllowedChars As String
            strAllowedChars = CType(Utility.getConfigValue("ADAllowedCharsInADACName"), String)
            ' Replace invalid characters with empty strings.
            GetCleanName = Regex.Replace(strIn, "[^\w" & strAllowedChars & "]", "")
        End Function

        Private Sub SendErrorEmail(ByVal strFunName As String, ByVal strErrMsg As String)
            Dim strMessageSubject As String = String.Concat(Utility.getConfigValue("HRDW_ErrorMailSubject"), " in ", strFunName)
            SendErrEmail(strMessageSubject, strErrMsg)
        End Sub
#End Region

    End Class
End Namespace
