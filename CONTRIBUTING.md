# Contribution Guide

For both PowerShell and Python we do our best to follow best practice standards. The following guide will walk you through the standards we follow.

## Help Wanted

We are working to standardize the repository. Any help would be welcomed with [updating our Python code to meet these standards](https://github.com/dell/OpenManage-Enterprise/issues/62)

## General Practices

- Make sure any pull requests to the repo rebase cleanly without conflict on master
- Commits should be signed off with your name in the format `Signed-off-by: FirstName LastName <gelante@someemail.domain` at the end. A good commit looks like this:

        file_I_modified: General description of change <---- this is the title
        - If you didn't modify one specific file then use a descriptive message for the title
        - Another description of a change you made
        - A third description of a change you made

        Signed-off-by: FirstName LastName <gelante@someemail.domain>

- If you write both a PowerShell script and a Python script or if a PowerShell/Python script already exists, the names should be the same with PowerShell scripts using the `<verb>-ThePurpose` format and Python using `verb_the_purpose` format.
  - You can find approved PowerShell verbs [here](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7)
- If your code is addressing an issue use the `#<ticket_number>` syntax inside of the commit message to reference the ticket.
- Before writing functions for common functionality like getting a device ID, accessing a REST resource, etc check out [Library Code](#library-code). Before accepting pull requests, if you rewrite a function already listed here we will probably ask you to refactor to use the library code.
- Whenever possible use odata filters instead of performing an exhaustive search of a dictionary. The [Get-Data](docs/powershell_library_code.md#Interact_with_an_API_Resource) for PowerShell and the [get_data](docs/python_library_code.md#Interact_with_an_API_Resource) provide a filter argument you can use for data retrieval. odata does not supported filtering on nested values so sometimes the `bad` method is unavoidable, but otherwise a filter can be used. This is particularly important to make our scripts scale efficiently for large deployments with tens of thousands of servers. Below are some common odata filters.
  - Getting a group ID from its name: `https://<ome_ip>/api/GroupService/Groups?$filter=Name eq '<group_name>'`
  - Get a device ID from its name `https://%<ome_ip>/api/DeviceService/Devices?$filter=DeviceName eq '<device_name>'`
  - Get a device ID from its service tag `https://%<ome_ip>/api/DeviceService/Devices?$filter=DeviceServiceTag eq '<service_tag>'`

#### Bad

    device_list = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address)
    for device_dictionary in device_list:
        if device_dictionary['DeviceName'] == device_name:
            device_id = device_dictionary['Id']
            break

#### Good

    requests.get('https://%s/api/DeviceService/Devices?$filter=DeviceName eq \'AHostName\' headers=authenticated_headers, verify=False)

    # PowerShell
    Get-Data "https://$($IpAddress)/api/DeviceService/Devices" "DeviceName eq `'$($DeviceName)`'"

    # Python
    get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address, "DeviceName eq \'%s\'" % device_name)

## PowerShell

- Must be tested and run against PowerShell 7
- Names must use [approved PowerShell verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7)
- We suggest for development you use [Visual Studio Code](https://code.visualstudio.com/download). It provides a `Format Document` function which automatically updates your PowerShell code to follow best practices. If you would rather use something else you can use [Get-FirmwareBaselines.ps1](Core/PowerShell/Get-FirmwareBaselines.ps1) as a reference for our preferred PowerShell coding practices.
- If for whatever reason the [Get-Data](docs/powershell_library_code.md#Interact-with-an-API-Resource) function does not suit your needs, use the `Invoke-RestMethod` function unless you have a specific reason to use `Invoke-WebRequest`.
- Provide documentation for all functions. For example:

        function Get-UniqueFileName {
        <#
            .SYNOPSIS
                Get a unique file name for the provided file

            .DESCRIPTION
                Resolves any relative paths to a full path and if the file already exists adds (#) to the filename and
                returns it.

            .PARAMETER FilePath
                A file path to a target location. Ex: '.\test.csv'

            .OUTPUTS
                The output of the function is in the variable FilePath and contains the full file path to the provided
                file. For example if .\test.csv were provided, this could resolve to 
                "C:\Users\grant\Documents\code\OpenManage-Enterprise\test.csv"
            #>

- When handling credentials use the `pscredential` type. Wherever possible take advantage of passing credentials directly. Unless absolutely necessary you should not need to do things like `$Variable = $Credentials.Password`. Many functions (like `Invoke-RestMethod`) support the `-Credential` argument which allows you to pass the `pscredential` argument directly.

## Python

There is a great tutorial on writing good Python code [here](https://realpython.com/python-pep8/).

- Must be tested and run against Python 3
- Adhere to PEP8 and PEP484. The easist way to adhere to PEP8 is to use PyLint. PyCharm provides [pylint as a plugin](https://plugins.jetbrains.com/plugin/11084-pylint) as does [vscode](https://code.visualstudio.com/docs/python/linting#_pylint). Alternatively it can be run from the command line.
- Use type definitions in your function definitions. Ex:

#### Bad

    authenticate(ome_ip_address, ome_username, ome_password):

#### Good

    authenticate(ome_ip_address: str, ome_username: str, ome_password: str) -> dict:

- All functions should be documented using the below docstring style. Make sure in the returns section to include the return type.

        """
        Authenticates with OME and creates a session

        Args:
            ome_ip_address: IP address of the OME server
            ome_username:  Username for OME
            ome_password: OME password

        Returns: A dictionary of HTTP headers

        Raises:
            Exception: A generic exception in the event of a failure to connect.

        Notes:
            Any notes you might have
        """

- Returns should happen in your main function. We prefer not to have scripts exit from sub functions. Instead you can raise an exception using the `raise` keyword or return a value like -1 in the event of a failure. Just make sure what you return is consistent with the return type you advertise in the function header. For example, do not return None if the function's return type should be dict.

#### Bad

    def func1(value: bool):
        if value:
            print("Yay")
        else:
            print("Boo")
            exit(1)

    def main(somearg: int):
        func1(False)

#### Good

    def func1(value: bool):
        if value:
            print("Yay")
        else:
            print("Boo")
            raise Exception("Don't give me false values!")

    def main(somearg: int):
        try:
            func1(False)
        Exception as error:
            print("Oh no - there was an exception: ", str(error))

- If you use libraries that require installation separately from a base install Python protect your code from module import errors and tell users how to install those dependencies:

#### Bad

    import urllib3

#### Good

    try:
        import urllib3
    except ModuleNotFoundError:
        print("This program requires urllib3. To install it on most systems run: "
            "`pip install requests urllib3`")

- We use standard PEP8 variable naming conventions. 
  - Variables should generally follow this pattern `something_descriptive`. 
  - Classes should be in the form `MyClass`. 
  - Methods should follow the pattern `description_of_method`
  - Constants should follow the pattern `A_CONSTANT`
- If you need to print complex data use `pprint`
- If you need an example to use as a template see [invoke_discover_device.py](Core/Python/invoke_discover_device.py)

## Library Code

Every script in this repository should be stand alone and copy and pastable. This has the unfortunate side effect of complicating code reuse. In an effort to standardize things we ask you use the standard functions we provide below for common tasks.

[Python Library Code](docs/python_library_code.md)

[PowerShell Library Code](docs/powershell_library_code.md)