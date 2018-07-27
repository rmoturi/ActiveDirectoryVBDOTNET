'Import required namespaces
Imports System
Imports System.Text
Imports System.Data
Imports System.Diagnostics
Imports System.Data.SqlClient
Imports System.DirectoryServices
Imports ActiveDs
Imports System.Collections.Generic
Imports System.Security.Principal

Module UpdateADUsers

    Private Const ADS_GROUP_TYPE_BUILTIN As Int32 = &H1
    Private Const ADS_GROUP_TYPE_GLOBAL As Int32 = &H2
    Private Const ADS_GROUP_TYPE_LOCAL As Int32 = &H4
    Private Const ADS_GROUP_TYPE_UNIVERSAL As Int32 = &H8
    Private Const ADS_GROUP_TYPE_SECURITY_ENABLED As Int32 = &H80000000
    Private blnProcessUsers As Boolean
    Private blnProcessUserGroups As Boolean
    Private blnCleanUpPortalSecurity As Boolean
    Private strDBServerName As String = String.Empty
    Private strADPath As String = My.Settings.ADPath 
    Private strLDAPPath As String = My.Settings.LDAPPath
    Private strDBName As String = "PM_Shared"

#Region " 'AD User Account statuses"
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

    Sub Main(ByVal ParamArray args() As String)
        'Declare local variables
        Dim st As New StackTrace
        Dim intI As Integer
        Dim sf As StackFrame
        Dim strErrorLog As New StringBuilder
        Dim strArgs As String()

        Try
            strArgs = args(0).Split("|".ToCharArray())
            If strArgs.Length > 0 Then
                strDBServerName = strArgs(0)
                If strArgs(1) = "0" Then blnProcessUsers = True
                If strArgs(1) = "1" Then blnProcessUserGroups = True
                If strArgs(1) = "2" Then blnCleanUpPortalSecurity = True
                If strArgs.Length > 2 Then strDBName = strArgs(2).Trim()
            End If

            If blnCleanUpPortalSecurity Then
                Console.WriteLine("Clean up ShareEntitySecurity: Started")
                CleanUpShareEntitySecurity()
                Console.WriteLine("Clean up ShareEntitySecurity: Completed")
            Else
                'Loop through domains

                Console.WriteLine("Update Active Directory to MsgPortalADUsers & MsgPortalADUserGroups : Started")
                WriteToTextFile("Update Active Directory to MsgPortalADUsers & MsgPortalADUserGroups : Started", False)

                For Each domain As String In GetDomainList()
#If DEBUG Then
                    
                    If domain.ToLower.Equals("corp") Then
                        UpdateADUsersList(domain)
                    End If
#Else
                    If Not domain.ToLower.Equals("takatacorp") Then
                        UpdateADUsersList(domain)
                    End If
#End If
                Next

                Console.WriteLine("Update Active Directory to MsgPortalADUsers & MsgPortalADUserGroups : Completed")
                WriteToTextFile("Update Active Directory to MsgPortalADUsers & MsgPortalADUserGroups : Completed")

            End If
            System.Threading.Thread.CurrentThread.Join(20000)
        Catch ex As Exception
            'Handle errors raised locally with appropriate log messages and arguments
            For intI = 0 To st.FrameCount - 1
                sf = st.GetFrame(intI)
                strErrorLog.Append("Method Name: ").Append(sf.GetMethod.Name).Append("Line Number: ").Append(sf.GetFileLineNumber().ToString)
            Next intI
            LogError(ex, strErrorLog.ToString & ex.InnerException.ToString)
            WriteToTextFile(ex.Message.ToString + ex.InnerException.ToString)
        End Try
    End Sub

    'Update AdUsers and Groups
    Private Sub UpdateADUsersList(ByVal domain As String)
        Dim dstInParam As New CDataSet
        Dim dstGroups As New CDataSet
        Dim st As New StackTrace
        Dim intI As Integer
        Dim sf As StackFrame
        Dim strErrorLog As New StringBuilder
        Dim strConnectionString As New StringBuilder
        Dim drCurrent As DataRow = Nothing
        Dim drCurrentGroup As DataRow = Nothing
        Dim intCount, intCountGroups As Integer

        Try
            'Construct the database string
            strConnectionString = strConnectionString.Append("server=").Append(strDBServerName).Append(";database=").Append(strDBName).Append(";uid=SharedUser;password=NIVRI;")
            Using objConn As New SqlConnection(strConnectionString.ToString)

                If blnProcessUsers Then
                    'Create an instance of a DataAdapter
                    Using daEmployees As New SqlDataAdapter("Select * From MsgPortalADUsers", objConn)

                        'Create an instance of a DataSet, and retrieve data from the MsgPortalADUsers table
                        Using dsSharedEmployees As New DataSet("MsgPortalADUsers")

                            daEmployees.FillSchema(dsSharedEmployees, SchemaType.Source, "MsgPortalADUsers")
                            daEmployees.Fill(dsSharedEmployees, "MsgPortalADUsers")

                            'Create a new instance of a DataTable
                            Using objCommandBuilderEmployees As New SqlCommandBuilder(daEmployees)
                                Using tblEmployees As DataTable = dsSharedEmployees.Tables("MsgPortalADUsers")

                                    dstInParam.Clear()
                                    dstInParam = GetUsersList(domain)

                                    Console.WriteLine("Started processing users with domain : " & domain.ToString)
                                    WriteToTextFile("Started processing users with domain : " & domain.ToString)

                                    If 0 < dstInParam.DataSets.Count Then
                                        For intCount = 0 To dstInParam.DataSets.Count - 1
                                            With dstInParam.DataSets(intCount)
                                                'Search for the current username in the database
                                                drCurrent = tblEmployees.Rows.Find(.Fields("UserName").FieldValue)
                                                If drCurrent Is Nothing Then
                                                    'Insert new record if not found
                                                    drCurrent = tblEmployees.NewRow()
                                                    drCurrent("UserName") = .Fields("UserName").FieldValue
                                                    drCurrent("FullName") = .Fields("FullName").FieldValue
                                                    drCurrent("Email_Address") = .Fields("Email_Address").FieldValue
                                                    drCurrent("First_Name") = .Fields("First_Name").FieldValue
                                                    drCurrent("Last_Name") = .Fields("Last_Name").FieldValue
                                                    drCurrent("ExchangeHostName") = .Fields("ExchangeHostName").FieldValue
                                                    drCurrent("UserPrincipalName") = .Fields("UserPrincipalName").FieldValue
                                                    If .Fields.Exists("HideFromAddressBook") AndAlso Not .Fields("HideFromAddressBook").FieldValue = String.Empty Then
                                                        drCurrent("HideFromAddressBook") = CType(.Fields("HideFromAddressBook").FieldValue, Boolean)
                                                    End If
                                                    drCurrent("rowguid") = System.Guid.NewGuid
                                                    drCurrent("IsActive") = .Fields("IsActive").FieldValue
                                                    drCurrent("IsUserNotified") = Boolean.FalseString
                                                    tblEmployees.Rows.Add(drCurrent)
                                                Else
                                                    'Update existing records
                                                    drCurrent.BeginEdit()
                                                    drCurrent("FullName") = .Fields("FullName").FieldValue
                                                    drCurrent("Email_Address") = .Fields("Email_Address").FieldValue
                                                    drCurrent("First_Name") = .Fields("First_Name").FieldValue
                                                    drCurrent("Last_Name") = .Fields("Last_Name").FieldValue
                                                    drCurrent("ExchangeHostName") = .Fields("ExchangeHostName").FieldValue
                                                    drCurrent("UserPrincipalName") = .Fields("UserPrincipalName").FieldValue
                                                    If .Fields.Exists("HideFromAddressBook") AndAlso Not .Fields("HideFromAddressBook").FieldValue = String.Empty Then
                                                        drCurrent("HideFromAddressBook") = CType(.Fields("HideFromAddressBook").FieldValue, Boolean)
                                                    End If
                                                    drCurrent("IsActive") = .Fields("IsActive").FieldValue
                                                    drCurrent.EndEdit()
                                                End If
                                            End With
                                        Next
                                    End If
                                    daEmployees.Update(dsSharedEmployees, "MsgPortalADUsers") : Console.WriteLine("Completed processing users for domain : " & domain.ToString)
                                    WriteToTextFile("Completed processing users for domain : " & domain.ToString)
                                End Using
                            End Using
                        End Using
                    End Using
                End If


                If blnProcessUserGroups Then
                    dstInParam.Clear()
                    dstInParam = GetUsersList(domain)
                    Console.WriteLine(DateTime.Now().ToString + " ---Started processing usergroups with domain : " & domain)
                    WriteToTextFile(DateTime.Now().ToString + " ---Started processing usergroups with domain : " & domain)

                    If 0 < dstInParam.DataSets.Count Then
                        Dim ADUserName As String = String.Empty
                        For intCount = 0 To dstInParam.DataSets.Count - 1 'For each User

                            'Get UserName for the current user from ActiveDirectory resultset
                            ADUserName = dstInParam.DataSets(intCount).Fields("UserName").FieldValue

                            Console.WriteLine("Started processing usergroups for : " & ADUserName)
                            WriteToTextFile("Started processing usergroups for : " & ADUserName)

                            'RM - Get MsgPortalADUserGroups for the current user
                            Using daEmployeeUserGroups As New SqlDataAdapter(GetSqlStringForUserName(ADUserName), objConn)
                                Using dsSharedEmployeeGroups As New DataSet("MsgPortalADUserGroups")
                                    daEmployeeUserGroups.FillSchema(dsSharedEmployeeGroups, SchemaType.Source, "MsgPortalADUserGroups")
                                    daEmployeeUserGroups.Fill(dsSharedEmployeeGroups, "MsgPortalADUserGroups")

                                    'Create a new instance of a DataTable
                                    Using objCommandBuilderEmployeeGroups As New SqlCommandBuilder(daEmployeeUserGroups)
                                        Using tblEmployeeUserGroups As DataTable = dsSharedEmployeeGroups.Tables("MsgPortalADUserGroups")
                                            'AcceptChanges before making changes to DataRows, this will keep track of the changes correctly
                                            tblEmployeeUserGroups.AcceptChanges()

                                            For intCountGroups = 0 To dstInParam.DataSets(intCount).DataSets("Groups").DataSets.Count - 1 'For each ADGroup for the current user
                                                'Get all groups for the current user
                                                dstGroups = dstInParam.DataSets(intCount).DataSets("Groups").DataSets(intCountGroups)

                                                'Check if the username has the group, if not add it to tblEmployeeUserGroups
                                                If tblEmployeeUserGroups.Rows.Find(New String() {dstInParam.DataSets(intCount).Fields("UserName").FieldValue, dstGroups.Fields("GroupName").FieldValue}) Is Nothing Then
                                                    drCurrentGroup = tblEmployeeUserGroups.NewRow
                                                    drCurrentGroup.Item("UserGroupID") = Guid.NewGuid
                                                    drCurrentGroup.Item("UserName") = dstInParam.DataSets(intCount).Fields("UserName").FieldValue
                                                    drCurrentGroup.Item("GroupName") = dstGroups.Fields("GroupName").FieldValue
                                                    drCurrentGroup.Item("Active") = Boolean.TrueString
                                                    drCurrentGroup.Item("Type") = dstGroups.Fields("Type").FieldValue
                                                    drCurrentGroup.Item("Scope") = dstGroups.Fields("Scope").FieldValue
                                                    tblEmployeeUserGroups.Rows.Add(drCurrentGroup)
                                                Else
                                                    'RM - Check if the username/groupname combination exists in the tblEmployeeUserGroups
                                                    drCurrentGroup = tblEmployeeUserGroups.Rows.Find(New String() {dstInParam.DataSets(intCount).Fields("UserName").FieldValue, dstGroups.Fields("GroupName").FieldValue})

                                                    'RM - if found but not active, set it to active
                                                    If drCurrentGroup.Item("Active").ToString.Equals("False") Then
                                                        drCurrentGroup.BeginEdit()
                                                        drCurrentGroup.Item("Active") = Boolean.TrueString
                                                        drCurrentGroup.EndEdit()
                                                    Else
                                                        'RM - SetModified is used as an indication to say this record was compared with ADUserGroup record
                                                        If drCurrentGroup.RowState.Equals(DataRowState.Unchanged) Then
                                                            drCurrentGroup.SetModified()
                                                        End If

                                                    End If

                                                End If
                                            Next

                                            'RM - set all rows that were not present in the active directory dataset as inactive
                                            SetUnProcessedRowsAsInactive(tblEmployeeUserGroups, ADUserName)

                                            If (dsSharedEmployeeGroups.HasChanges) Then
                                                daEmployeeUserGroups.Update(dsSharedEmployeeGroups, "MsgPortalADUserGroups")
                                            End If
                                        End Using
                                    End Using
                                End Using
                            End Using
                        Next
                    End If

                    Console.WriteLine(DateTime.Now().ToString + " ---Completed processing usergroups with domain : " & domain)
                    WriteToTextFile(DateTime.Now().ToString + " ---Completed processing usergroups with domain : " & domain)

                End If
                
            End Using
        Catch ex As Exception
            'Handle errors raised locally with appropriate log messages and arguments
            For intI = 0 To st.FrameCount - 1
                sf = st.GetFrame(intI)
                strErrorLog.Append("Method Name: ").Append(sf.GetMethod.Name).Append("Line Number: ").Append(sf.GetFileLineNumber().ToString)
            Next intI
            LogError(ex, strErrorLog.ToString & dstInParam.Fields("UserName").FieldValue & "Inner Exception: " & ex.InnerException.ToString)
        End Try
    End Sub

#Region "Helper Functions UpdateADUsersList "
    'RM - set all rows in tblEmployeeUserGroups to inactive
    Private Sub SetUnProcessedRowsAsInactive(ByRef tblEmployeeUserGroups As DataTable, ByVal username As String) ' ByVal lastNameFirstChar As String)
        Try
            For Each dr As DataRow In tblEmployeeUserGroups.Rows
                If dr.RowState.Equals(DataRowState.Unchanged) Then
                    dr.BeginEdit()
                    dr.Item("Active") = Boolean.FalseString
                    dr.EndEdit()
                End If
            Next
        Catch ex As Exception
            LogError(ex, "SetUnProcessedRowsAsInactive", True)
        End Try
    End Sub

    'RM - get records from MsgPortalADUserGroups for the username
    Private Function GetSqlStringForUserName(ByVal username As String) As String
        Dim strSql As String
        strSql = "SELECT * FROM MsgPortalADUserGroups WHERE UserName = '" & username & "' "
        Return strSql
    End Function
#End Region

    'Seperate the exchange server name
    Private Function GetExchangeHomeName(ByVal strExchServerHomeName As String) As String
        GetExchangeHomeName = strExchServerHomeName.Split("/".ToCharArray)(5).Substring(3)
    End Function

    Dim lsDomain As New List(Of String)
    Private Function GetDomainList() As List(Of String)
        Dim theForest As ActiveDirectory.Forest = ActiveDirectory.Forest.GetCurrentForest()
        Dim myDomains As ActiveDirectory.DomainCollection = theForest.Domains
        ' Dim domainName As String
        Dim domains As New Dictionary(Of String, String)
        ' Dim pdcName As String
        Try
            For Each myDomain As ActiveDirectory.Domain In myDomains
                'lsDomain.Add(myDomain.PdcRoleOwner.Name)
                If myDomain.Name.Contains(".") Then
                    lsDomain.Add(myDomain.Name.Split(".")(0))
                Else
                    lsDomain.Add(myDomain.Name)
                End If
            Next
            lsDomain.Add("Corp") 'New domain for Joyson outside the current Forest
        Catch ex As Exception
            Console.WriteLine("Error in GetDomainList" + ex.InnerException.Message)
        End Try

        Return lsDomain
    End Function

    'Get list of users for each domain
    Private Function GetUsersList(ByVal strDomain As String) As CDataSet
        'Declare local variables
        Dim srResult As SearchResult = Nothing
        Dim dstOutData As New CDataSet
        Dim strNewDSName As String = String.Empty
        Dim strDocumentName As String = "D"
        Dim strExchangeHomeName As String = String.Empty
        Dim intMemberOfCnt As Integer
        Dim strGroupTypes As String()
        Dim strGroupName As String
        Dim strADUserName As String
        Dim strLDAPUserName As String = String.Empty
        Dim strLDAPPassword As String = String.Empty
        Dim startTime As DateTime
        Dim endTime As DateTime
        If (strDomain.ToLower.Equals("corp")) Then
            strLDAPUserName = My.Settings.LDAPUserNameJoyson
            strLDAPPassword = My.Settings.LDAPPasswordJoyson
        Else
            strLDAPUserName = My.Settings.LDAPUserName
            strLDAPPassword = My.Settings.LDAPPassword
        End If

        GetUsersList = Nothing
        Try
            'Initialize variables
            Using dsSearcher As New DirectorySearcher
                Using deContextEntry As New DirectoryEntry(GetLDAPPathForDomain(strDomain), strLDAPUserName, strLDAPPassword)

                    'Set search root and filter
                    dsSearcher.SearchRoot = deContextEntry
                    dsSearcher.Filter = String.Format("(&(objectClass=user)(objectCategory=person))") '(cn=Osborne, Mia)(cn=moturi*)
                    

                    dsSearcher.PageSize = 1000

                    'Determine what properties are needed
                    dsSearcher.PropertiesToLoad.Add("mail")
                    dsSearcher.PropertiesToLoad.Add("cn")
                    dsSearcher.PropertiesToLoad.Add("distinguishedName")
                    dsSearcher.PropertiesToLoad.Add("sn")
                    dsSearcher.PropertiesToLoad.Add("givenname")
                    dsSearcher.PropertiesToLoad.Add("msExchHomeServerName")
                    dsSearcher.PropertiesToLoad.Add("userPrincipalName")
                    dsSearcher.PropertiesToLoad.Add("sAMAccountName")
                    dsSearcher.PropertiesToLoad.Add("memberof")
                    dsSearcher.PropertiesToLoad.Add("groupType")
                    dsSearcher.PropertiesToLoad.Add("msExchHideFromAddressLists")
                    dsSearcher.PropertiesToLoad.Add("userAccountControl")
                    'Set sort direction
                    dsSearcher.Sort.PropertyName = "cn"
                    dsSearcher.Sort.Direction = SortDirection.Ascending

                    'Set other properties
                    dsSearcher.SearchScope = SearchScope.Subtree
                    If (strDomain.ToLower.Equals("corp")) Then
                        dsSearcher.ReferralChasing = ReferralChasingOption.All 'Setting it to None doesn't work for Joyson Forest!
                    Else
                        dsSearcher.ReferralChasing = ReferralChasingOption.None
                    End If

                    'RM - start time
                    startTime = DateTime.Now()

                    'Perform the search
                    Using srResults As SearchResultCollection = dsSearcher.FindAll()
                        If srResults IsNot Nothing And srResults.Count > 0 Then

                            Console.WriteLine(DateTime.Now().ToString + " ---Got " + srResults.Count.ToString + " users for domain " + strDomain + " in " + Convert.ToString((DateTime.Now() - startTime).TotalMinutes()) + " minutes")
                            WriteToTextFile(DateTime.Now().ToString + " ---Got " + srResults.Count.ToString + " users for domain " + strDomain + " in " + Convert.ToString((DateTime.Now() - startTime).TotalMinutes()) + " minutes")

                            'Loop through the result set
                            For Each srResult In srResults
                                If srResult.Properties.Contains("mail") AndAlso srResult.Properties.Contains("sn") AndAlso srResult.Properties.Contains("givenname") Then
                                    strNewDSName = strDocumentName & String.Concat(dstOutData.DataSets.Count() + 1)
                                    dstOutData.AppendDataSets(strNewDSName)

                                    strADUserName = GetNetBIOSName(srResult.Properties("distinguishedName")(0).ToString())

                                    dstOutData.DataSets(strNewDSName).Fields.Add("UserName", strADUserName)
                                    dstOutData.DataSets(strNewDSName).Fields.Add("FullName", srResult.Properties("cn")(0).ToString())
                                    dstOutData.DataSets(strNewDSName).Fields.Add("EMail_Address", srResult.Properties("mail")(0).ToString())
                                    dstOutData.DataSets(strNewDSName).Fields.Add("First_Name", srResult.Properties("givenname")(0).ToString())
                                    dstOutData.DataSets(strNewDSName).Fields.Add("Last_Name", srResult.Properties("sn")(0).ToString())

                                    strExchangeHomeName = String.Empty
                                    If Not IsNothing(srResult.Properties("msExchHomeServerName")) Then
                                        If srResult.Properties("msExchHomeServerName").Count > 0 Then
                                            strExchangeHomeName = GetExchangeHomeName(srResult.Properties("msExchHomeServerName")(0).ToString())
                                        End If
                                    End If
                                    dstOutData.DataSets(strNewDSName).Fields.Add("ExchangeHostName", strExchangeHomeName)

                                    If Not IsNothing(srResult.Properties("userPrincipalName")) Then
                                        If srResult.Properties("userPrincipalName").Count > 0 Then
                                            dstOutData.DataSets(strNewDSName).Fields.Add("UserPrincipalName", srResult.Properties("userPrincipalName").Item(0).ToString)
                                        Else
                                            dstOutData.DataSets(strNewDSName).Fields.Add("UserPrincipalName", String.Empty)
                                        End If
                                    End If

                                    If Not IsNothing(srResult.Properties("msExchHideFromAddressLists")) Then
                                        If srResult.Properties("msExchHideFromAddressLists").Count > 0 Then
                                            dstOutData.DataSets(strNewDSName).Fields.Add("HideFromAddressBook", srResult.Properties("msExchHideFromAddressLists").Item(0).ToString)
                                        Else
                                            dstOutData.DataSets(strNewDSName).Fields.Add("HideFromAddressBook", Boolean.FalseString)
                                        End If
                                    End If
                                    'Read User Account status - Active or Inactive
                                    If Not IsNothing(srResult.Properties("userAccountControl")) Then
                                        Dim MyUserFlags As AdsUserFlags = CType(srResult.Properties("userAccountControl").Item(0).ToString, AdsUserFlags)
                                        If (MyUserFlags = AdsUserFlags.AccountDisabled Or MyUserFlags = AdsUserFlags.AccountDisabledNormal Or _
                                                    MyUserFlags = AdsUserFlags.AccountDisabledNormalPwdNotReq Or MyUserFlags = AdsUserFlags.AccountDisabledNormalPwdDoesNotExpire) Then
                                            dstOutData.DataSets(strNewDSName).Fields.Add("IsActive", Boolean.FalseString)
                                        Else
                                            dstOutData.DataSets(strNewDSName).Fields.Add("IsActive", Boolean.TrueString)
                                        End If
                                    Else
                                        dstOutData.DataSets(strNewDSName).Fields.Add("IsActive", Boolean.TrueString)
                                    End If

                                    If blnProcessUserGroups Then
                                        dstOutData.DataSets(strNewDSName).AppendDataSets("Groups")

                                        If Not IsNothing(srResult.Properties("memberof")) Then
                                            'RM - write something to console to prevent the lock error
                                            Console.Write(strADUserName + " has " + srResult.Properties("memberof").Count.ToString + " groups")

                                            For intMemberOfCnt = 0 To srResult.Properties("memberof").Count - 1
                                                dstOutData.DataSets(strNewDSName).DataSets("Groups").AppendDataSets(("Group" & intMemberOfCnt.ToString))
                                                strGroupName = GetGroupName(srResult.Properties("memberof").Item(intMemberOfCnt).ToString)
                                                dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("GroupName", strGroupName)
                                                strGroupTypes = GetGroupProperties(strGroupName)
                                                If Not strGroupTypes Is Nothing AndAlso strGroupTypes.Length > 0 Then
                                                    dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("Type", strGroupTypes(2))
                                                    dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("Scope", strGroupTypes(1))
                                                    dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("UserGroupID", strGroupTypes(0))
                                                Else
                                                    dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("Type", String.Empty)
                                                    dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("Scope", String.Empty)
                                                    dstOutData.DataSets(strNewDSName).DataSets("Groups").DataSets(("Group" & intMemberOfCnt.ToString)).Fields.Add("UserGroupID", String.Empty)
                                                End If
                                            Next
                                        End If
                                    End If
                                End If
                            Next
                        End If
                    End Using
                End Using
            End Using
            GetUsersList = dstOutData
            'RM - end time
            endTime = DateTime.Now()

            Console.WriteLine("Got all users and groups in mins: " + (endTime - startTime).TotalMinutes.ToString)
            WriteToTextFile("Got all users and groups in mins: " + (endTime - startTime).TotalMinutes.ToString)

        Catch ex As Exception
            'Handle errors raised locally with appropriate log messages and arguments
            LogError(ex, "Input: " & strDomain & "Inner Exception: " & ex.InnerException.ToString)
        End Try
        Return GetUsersList
    End Function

#Region "Helper Functions"
    ''' <summary>
    ''' Appends text to file. Creates new file if file not found.
    ''' </summary>
    ''' <param name="text"></param>
    ''' <remarks></remarks>
    Private Sub WriteToTextFile(ByVal text As String, Optional ByVal blnAppend As Boolean = True)
        Using file As New System.IO.StreamWriter(My.Settings.LogFilePath, blnAppend)
            file.WriteLine(text)
        End Using
    End Sub

    ''' <summary>
    ''' Gets domain part of the AD Username
    ''' </summary>
    ''' <param name="userName">domain\username</param>
    ''' <returns>returns only the domain</returns>
    ''' <remarks></remarks>
    Private Function GetDomainForUserName(ByVal userName As String) As String
        If userName.Length > 0 And userName.Contains("\") Then
            Return userName.Split("\")(0)
        Else
            Return ""
        End If
    End Function

    ''' <summary>
    '''  Gets domain part of the AD Username
    ''' </summary>
    ''' <param name="userName">domain\username</param>
    ''' <returns>username without the domain</returns>
    ''' <remarks></remarks>
    Private Function RemoveDomainForUserName(ByVal userName As String) As String
        If userName.Length > 0 And userName.Contains("\") Then
            Return userName.Split("\")(1)
        Else
            Return userName
        End If
    End Function

    'Retrieve the NETBIOS Name
    Private Function GetNetBIOSName(ByVal strFullName As String) As String
        'Declare local variables
        Dim objTrans As New NameTranslate
        GetNetBIOSName = String.Empty
        Try
            'Get the domain\username
            objTrans = CreateObject("NameTranslate")
            objTrans.Init(3, strFullName)
            objTrans.Set(1, strFullName)
            GetNetBIOSName = objTrans.Get(3)
        Catch ex As Exception
            'Handle errors raised locally with appropriate log messages and arguments
            LogError(ex, "Input: " & strFullName & "Inner Exception: " & ex.InnerException.ToString)
        End Try
        Return GetNetBIOSName
    End Function
#End Region

#Region "Helper Functions Group"
    ''' <summary>
    ''' Change LDAP path based on the domain
    ''' </summary>
    ''' <param name="domain"></param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Function GetLDAPPathForDomain(ByVal domain As String) As String
        Select Case domain.ToUpper()
            Case "NA"
                Return My.Settings.LDAPPathNA
            Case "CN"
                Return My.Settings.LDAPPathCN
            Case "EU"
                Return My.Settings.LDAPPathEU
            Case "JP"
                Return My.Settings.LDAPPathJP
            Case "TPSA"
                Return My.Settings.LDAPPathTPSA
            Case "TAKATACORP" '"IAP", "EGWCOM1", "PBTEMP", 
                Return strLDAPPath.Replace("DC=NA,", "")
            Case "CORP"
                Return My.Settings.LDAPPathJoyson  
        End Select

        Return strLDAPPath
    End Function

    Private Function GetGroupName(ByVal strFullGroupName As String) As String
        If strFullGroupName.Contains("\,") Then
            strFullGroupName = strFullGroupName.Replace("\,", "|")
            strFullGroupName = strFullGroupName.Split(New Char() {","c})(0).Split(New Char() {"="c})(1)
            GetGroupName = strFullGroupName.Replace("|", ",")
        Else
            GetGroupName = strFullGroupName.Split(New Char() {","c})(0).Split(New Char() {"="c})(1)
        End If
    End Function

    Private Function GetGroupProperties(ByVal strGroupName As String) As String()
        'Declare local variables
        Dim dsSearcher As DirectorySearcher = Nothing
        Dim srResult As SearchResult = Nothing
        Dim strGType As String() = Nothing
        Dim strGroupID As String
        Try
            If Not strGroupName = String.Empty AndAlso Not strGroupName Is Nothing Then

                'Initialize variables
                dsSearcher = New DirectorySearcher
                Using deContextEntry As New DirectoryEntry(strLDAPPath)

                    'Set search root and filter
                    dsSearcher.SearchRoot = deContextEntry
                    dsSearcher.Filter = String.Format("(&(objectCategory=Group)(objectClass=group)(cn=" & strGroupName & "))")
                    dsSearcher.PageSize = 1000

                    'Determine what properties are needed
                    dsSearcher.PropertiesToLoad.Add("cn")
                    dsSearcher.PropertiesToLoad.Add("distinguishedName")
                    dsSearcher.PropertiesToLoad.Add("groupType")
                    dsSearcher.PropertiesToLoad.Add("objectGUID")

                    'Set sort direction
                    dsSearcher.Sort.PropertyName = "cn"
                    dsSearcher.Sort.Direction = SortDirection.Ascending

                    'Set other properties
                    dsSearcher.SearchScope = SearchScope.Subtree
                    dsSearcher.ReferralChasing = ReferralChasingOption.None

                    'Perform the search
                    Using srResults As SearchResultCollection = dsSearcher.FindAll()

                        For Each srResult In srResults
                            Using deSearchRowEntry As DirectoryEntry = srResult.GetDirectoryEntry
                                If srResult.Properties.Contains("groupType") AndAlso srResult.Properties.Contains("objectGUID") Then
                                    If Not deSearchRowEntry Is Nothing Then
                                        strGroupID = deSearchRowEntry.Guid.ToString
                                    Else
                                        strGroupID = Guid.NewGuid.ToString
                                    End If
                                    strGType = GetGroupType(srResult.Properties("groupType")(0).ToString(), strGroupID)
                                End If
                            End Using
                        Next
                    End Using
                End Using
            End If

        Catch ex As Exception
            strGType = Nothing
            'Handle errors raised locally with appropriate log messages and arguments
            LogError(ex, "Input: " & strGroupName & "Inner Exception: " & ex.InnerException.ToString)
        End Try
        Return strGType
    End Function

    'Determined group type from the GroupType attribute
    Private Function GetGroupType(ByVal lngFlag As Long, ByVal strGroupID As String) As String()
        Dim strGroupType As String = strGroupID & "|"
        If ((lngFlag And ADS_GROUP_TYPE_BUILTIN) <> 0) Then
            strGroupType &= "Built-in" & "|"
        ElseIf ((lngFlag And ADS_GROUP_TYPE_GLOBAL) <> 0) Then
            strGroupType &= "Global" & "|"
        ElseIf ((lngFlag And ADS_GROUP_TYPE_LOCAL) <> 0) Then
            strGroupType &= "Local" & "|"
        ElseIf ((lngFlag And ADS_GROUP_TYPE_UNIVERSAL) <> 0) Then
            strGroupType &= "Universal" & "|"
        End If
        If ((lngFlag And ADS_GROUP_TYPE_SECURITY_ENABLED) <> 0) Then
            strGroupType &= "Security"
        Else
            strGroupType &= "Distribution"
        End If
        Return strGroupType.Split("|".ToCharArray())
    End Function
#End Region

    Private Sub CleanUpShareEntitySecurity()
        Dim objSearchResult As SearchResult = Nothing
        Dim strConnectionString As New StringBuilder
        Dim intCounter As Int32 = 0
        Try
            'Construct the database string
            strConnectionString = strConnectionString.Append("server=").Append(strDBServerName).Append(";database=").Append(strDBName).Append(";uid=SharedUser;password=NIVRI;")
            Using objConn As SqlConnection = New SqlConnection(strConnectionString.ToString)
                'get users from MsgPortalADUsers
                Using dsSharedEmployees As DataSet = New DataSet("MsgPortalADUsers")
                    Using objADAdapter As SqlDataAdapter = New SqlDataAdapter("SELECT RIGHT(UserName, CHARINDEX('\', REVERSE(UserName)) - 1) AS ADUserName, UserName FROM MsgPortalADUsers WHERE IsActive = 1 ORDER BY UserName", objConn)
                        objADAdapter.FillSchema(dsSharedEmployees, SchemaType.Source, "MsgPortalADUsers")
                        objADAdapter.Fill(dsSharedEmployees, "MsgPortalADUsers")
                    End Using
                    'Initialize variables
                    Using objDirectoryEntry As DirectoryEntry = New DirectoryEntry("GC://DC=TakataCorp,DC=com")
                        Using objDirectorySearcher As DirectorySearcher = New DirectorySearcher
                            'Set search root and filter
                            objDirectorySearcher.SearchRoot = objDirectoryEntry
                            'loop through datareader and check if account exists in AD
                            For intCounter = 0 To dsSharedEmployees.Tables("MsgPortalADUsers").Rows.Count - 1
                                objDirectorySearcher.Filter = String.Format("(SAMAccountName={0})", dsSharedEmployees.Tables("MsgPortalADUsers").Rows(intCounter).Item("ADUserName").ToString)
                                'Set other properties
                                objDirectorySearcher.SearchScope = SearchScope.Subtree
                                objDirectorySearcher.ReferralChasing = ReferralChasingOption.None
                                'Perform the search
                                objSearchResult = objDirectorySearcher.FindOne
                                Try
                                    'If srResults.Count = 0 Then
                                    If objSearchResult Is Nothing Then
                                        'if no results, set active to false
                                        'update the ShareEntitySecurity table
                                        objConn.Open()
                                        Using cmdUpdate As SqlCommand = objConn.CreateCommand()
                                            cmdUpdate.CommandTimeout = 10000
                                            cmdUpdate.CommandType = CommandType.StoredProcedure
                                            cmdUpdate.Parameters.AddWithValue("UserName", dsSharedEmployees.Tables("MsgPortalADUsers").Rows(intCounter).Item("UserName").ToString)
                                            cmdUpdate.CommandText = "spTNUpdateEntitySecurity"
                                            cmdUpdate.ExecuteNonQuery()
                                        End Using
                                        objConn.Close()
                                    End If
                                Catch ex As Exception
                                    LogError(ex, "CleanUpShareEntitySecurity:  spTNUpdateEntitySecurity Execution Failed " & ex.InnerException.ToString)
                                End Try
                            Next
                        End Using
                    End Using
                End Using
            End Using
        Catch ex As Exception
            LogError(ex, "Scheduled Task Failed : UpdateADUsers ==> CleanUpShareEntitySecurity: " & ex.InnerException.ToString)
        End Try
    End Sub
End Module