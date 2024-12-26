# -*- coding: utf-8 -*-
import threading
import random, json
import re  # Import regex for email detection
import os
import urlparse  # Use urlparse instead of urllib.parse
from copy import deepcopy
from java.net import URL
from java.awt import BorderLayout
from java.lang import Integer
from java.io import PrintWriter
from javax.swing.table import DefaultTableModel
from javax.swing.table import TableRowSorter
from javax.swing.table import DefaultTableCellRenderer
from javax.swing.SwingConstants import LEFT
from burp import IBurpExtender, IHttpListener, IContextMenuFactory, ITab
from java.util import ArrayList
from javax.swing import JMenuItem, JCheckBox, JPanel,JLabel, JTextField, JOptionPane, SwingUtilities, BoxLayout, JScrollPane, JTable, JSplitPane, JTabbedPane, JTextArea, JButton, Box

class CustomTableModel(DefaultTableModel):
    def getColumnClass(self, columnIndex):
        if columnIndex == 0:  # "Number" column
            return Integer  # Ensures numeric sorting
        if columnIndex == 5:  # "Content Length" column
            return Integer  # Ensures numeric sorting
        return str  # Default to string for other columns
    
# Custom cell renderer for left alignment
class LeftAlignRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)  # Explicit call to the parent class constructor
        self.setHorizontalAlignment(LEFT)  # Set alignment to LEFT

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab):
    HEADERS_FILE_PATH = os.path.join(os.getcwd(), "wordlists", "headers.txt")

    # Function to read headers from the file
    def read_headers_from_file(file_path):
        headers = []
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                for line in file:
                    header = line.strip()
                    if header:  # Ignore empty lines
                        headers.append(header)
        else:
            print("Headers file not found at:", file_path)
        return headers

    # Read headers from the file
    HEADERS_LIST = read_headers_from_file(HEADERS_FILE_PATH)
    ###############################################################################
    USER_AGENTS_PATH = os.path.join(os.getcwd(), "wordlists", "User-Agents.txt")
    def read_agents_from_file(file_path):
        agents = []
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                for line in file:
                    agent = line.strip()
                    if agent:  # Ignore empty lines
                        agents.append(agent)
        else:
            print("Headers file not found at:", file_path)
        return agents
    
    USER_AGENTS = read_agents_from_file(USER_AGENTS_PATH)

    
    def __init__(self):
        # Initialize the table with columns: Number, Host, Method, URL, Status Code
        self.log_table_model = CustomTableModel(["Number", "Host", "Method", "URL", "Status Code", "Content Length"], 0)
        self.log_table = JTable(self.log_table_model)
        self.row_sorter = TableRowSorter(self.log_table_model)  # Initialize the TableRowSorter
        self.log_table.setRowSorter(self.row_sorter)  # Attach the sorter to the table
        # Align the "Number" column to the left
        number_column = self.log_table.getColumnModel().getColumn(0)  # Get the "Number" column (index 0)
        number_column.setCellRenderer(LeftAlignRenderer())  # Apply the custom renderer
        
        number_column1 = self.log_table.getColumnModel().getColumn(5)  # Get the "Content Length" column (index 5)
        number_column1.setCellRenderer(LeftAlignRenderer())  # Apply the custom renderer


        self.request_text_area = JTextArea()
        self.response_text_area = JTextArea()
        self.request_headers_area = JTextArea()
        self.response_headers_area = JTextArea()
        self.messages = []  # To store message_info objects
        self.request_counter = 1  # Counter for numbering requests
        self.setup_ui()
        


    def setup_ui(self):
        self.log_table.setSelectionMode(0)  # Single selection
        self.log_table.getSelectionModel().addListSelectionListener(self.update_message_view)

        # Tabbed pane for the request details
        request_tabbed_pane = JTabbedPane()
        request_tabbed_pane.addTab("Raw", JScrollPane(self.request_text_area))
        request_tabbed_pane.addTab("Headers", JScrollPane(self.request_headers_area))

        # Tabbed pane for the response details
        response_tabbed_pane = JTabbedPane()
        response_tabbed_pane.addTab("Raw", JScrollPane(self.response_text_area))
        response_tabbed_pane.addTab("Headers", JScrollPane(self.response_headers_area))

        # Split pane for request and response (horizontal resizable)
        details_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_tabbed_pane, response_tabbed_pane)
        details_split_pane.setResizeWeight(0.5)
        details_split_pane.setContinuousLayout(True)
        details_split_pane.setDividerLocation(900)

        # Buttons for user actions
        button_panel = Box(BoxLayout.X_AXIS)
        send_to_repeater_button = JButton("Send to Repeater", actionPerformed=self.send_to_repeater)
        delete_selected_button = JButton("Delete Selected", actionPerformed=self.delete_selected_rows)
        delete_all_button = JButton("Delete All", actionPerformed=self.delete_all_rows)
        button_panel.add(send_to_repeater_button)
        button_panel.add(delete_selected_button)
        button_panel.add(delete_all_button)

        # Main split pane for log table and details (vertical resizable)
        main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.log_table), details_split_pane)
        main_split_pane.setResizeWeight(0.5)
        main_split_pane.setContinuousLayout(True)
        main_split_pane.setDividerLocation(300)

        # Main layout
        self.log_panel = JPanel(BorderLayout())
        self.log_panel.add(main_split_pane, BorderLayout.CENTER)
        self.log_panel.add(button_panel, BorderLayout.SOUTH)

    ############################################################################################################

    def update_message_view(self, event):
        if event.getValueIsAdjusting():
            return

        selected_row = self.log_table.getSelectedRow()
        if selected_row == -1:
            return

        actual_row = self.log_table.convertRowIndexToModel(selected_row)
        message_info = self.messages[actual_row]

        try:
            request_bytes = message_info.getRequest()
            if request_bytes:
                self.request_text_area.setText(self._helpers.bytesToString(request_bytes))
                self.request_headers_area.setText("\n".join(self._helpers.analyzeRequest(request_bytes).getHeaders()))
                # Scroll to the top for the request views
                self.request_text_area.setCaretPosition(0)
                self.request_headers_area.setCaretPosition(0)

            response_bytes = message_info.getResponse()
            if response_bytes:
                self.response_text_area.setText(self._helpers.bytesToString(response_bytes))
                self.response_headers_area.setText("\n".join(self._helpers.analyzeResponse(response_bytes).getHeaders()))
                # Scroll to the top for the response views
                self.response_text_area.setCaretPosition(0)
                self.response_headers_area.setCaretPosition(0)
        except Exception as e:
            print("[ERROR] update_message_view:", str(e))

    def send_to_repeater(self, event):
        selected_row = self.log_table.getSelectedRow()
        if selected_row == -1:
            print("[INFO] No row selected.")
            return

        actual_row = self.log_table.convertRowIndexToModel(selected_row)
        message_info = self.messages[actual_row]

        try:
            host = message_info.getHttpService()
            request_bytes = message_info.getRequest()
            self._callbacks.sendToRepeater(host.getHost(), host.getPort(), host.getProtocol() == "https", request_bytes, None)
        except Exception as e:
            print("[ERROR] send_to_repeater:", str(e))

    def delete_selected_rows(self, event=None):
        """
        Deletes the selected rows from the table and the corresponding entries in the messages list.
        """
        try:
            # Get the selected rows from the table
            selected_rows = self.log_table.getSelectedRows()
            if len(selected_rows) == 0:
                return

            # Remove rows in reverse order to avoid index shifting issues
            for row in reversed(selected_rows):
                model_index = self.log_table.convertRowIndexToModel(row)  # Convert view index to model index
                self.log_table_model.removeRow(model_index)  # Remove from table model
                del self.messages[model_index]  # Remove corresponding message
        except Exception as e:
            print("[ERROR] delete_selected_rows:", str(e))

    def delete_all_rows(self, event=None):
        """
        Deletes all rows from the table and clears the messages list.
        """
        try:
            # Remove all rows from the table model
            self.log_table_model.setRowCount(0)
            # Clear the messages list
            self.messages = []  # Compatible with all Python versions
        except Exception as e:
            print("[ERROR] delete_all_rows:", str(e))

    def getTabCaption(self):
        return "429 Bypasser"

    def getUiComponent(self):
        return self.log_panel
    ############################################################################################################

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("429 Bypasser")
        #print("Hello Burp")

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
    
    def getpath (self, content):
        request_info = self._helpers.analyzeRequest(content)
        url = request_info.getUrl()  # Get the URL of the request
        path = url.getPath()
        return path, url
    
    def getContentType(self, headers):
        # Search for the Content-Type header in the headers list
        for header in headers:
            if header.lower().startswith("content-type:"):
                # Split the header on ':' and strip whitespace to get the value
                return header.split(":", 1)[1].strip()
        return None
    
    def generatePollutedUrls(self, url, params_to_modify=None):
        # Parse the URL using urlparse
        parsed_url = urlparse.urlparse(str(url))
        base_path = parsed_url.path
        query_params = urlparse.parse_qs(parsed_url.query)

        polluted_urls = []

        # Define regex pattern to identify email addresses
        email_pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

        for param, values in query_params.items():
            if params_to_modify and param not in params_to_modify:
                continue

            if values:
                original_value = values[0]

                # Check if the value matches an email format
                if re.match(email_pattern, original_value):
                    username, domain = original_value.split("@")
                    extra_value = "{}2@{}".format(username, domain)  # Modify the email

                else:
                    extra_value = "{}2".format(original_value)  # Standard case

                # Polluted version with the extra value first
                polluted_query_first = {k: v[:] for k, v in query_params.items()}
                polluted_query_first[param].insert(0, extra_value)
                polluted_query_first_str = "&".join(
                    ["{}={}".format(k, v) for k, vals in polluted_query_first.items() for v in vals]
                )
                polluted_urls.append("{}?{}".format(base_path, polluted_query_first_str))

                # Polluted version with the extra value last
                polluted_query_last = {k: v[:] for k, v in query_params.items()}
                polluted_query_last[param].append(extra_value)
                polluted_query_last_str = "&".join(
                    ["{}={}".format(k, v) for k, vals in polluted_query_last.items() for v in vals]
                )
                polluted_urls.append("{}?{}".format(base_path, polluted_query_last_str))

        return polluted_urls

    def modify_body_with_null_bytes(self, http_service, headers, body, params_to_modify):
        content_type = self.getContentType(headers)
        modified_bodies = []
        null_byte_variants = ["%00", "%20", "%09", "%0d", "%0a"]
        
        if "application/json" in content_type:
            try:
                body_json = json.loads(body)
                parameters = params_to_modify if params_to_modify else body_json.keys()
                
                for param in parameters:
                    if param in body_json:
                        original_value = str(body_json[param])
                        for variant in null_byte_variants:
                            modified_json = body_json.copy()
                            modified_json[param] = original_value + variant
                            modified_body = json.dumps(modified_json)
                            modified_bodies.append(modified_body)
            except json.JSONDecodeError:
                print("Invalid JSON body")

        elif "application/x-www-form-urlencoded" in content_type:
            params = urlparse.parse_qs(body, keep_blank_values=True)
            parameters = params_to_modify if params_to_modify else params.keys()
            
            for param in parameters:
                if param in params:
                    original_value = params[param][0]
                    for variant in null_byte_variants:
                        modified_params = params.copy()
                        modified_params[param] = [original_value + variant]
                        modified_body = "&".join("{}={}".format(k, v[0]) for k, v in modified_params.items())
                        modified_bodies.append(modified_body)

        # Send modified requests with appended null byte characters
        for modified_body in modified_bodies:
            modified_request = self._helpers.buildHttpMessage(headers, modified_body)
            response = self._callbacks.makeHttpRequest(http_service, modified_request)
            status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
            request_info = self._helpers.analyzeRequest(response)
            path1 = request_info.getUrl().getPath()
            query1 = request_info.getUrl().getQuery()

            response_info = self._helpers.analyzeResponse(response.getResponse())
            response_headers = response_info.getHeaders()
            content_length1 = None
                
            for header in response_headers:
                if header.lower().startswith("content-length:"):
                    content_length1 = int(header.split(":")[1].strip())
                    break

            if query1 is None:
                url1 = path1
            else:
                url1 = path1 + "?" + query1
            method1 = request_info.getMethod()
            host1 = response.getHttpService().getHost()
                    
            # Log the request in the table with a placeholder for status code
            self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
            self.messages.append(response)
            self.request_counter += 1
            #print("Sent modified request with null byte variant, received status:", status_code)
    
    def getRequestHeadersAndBody(self, content):
        request = content.getRequest()
        request_data = self._helpers.analyzeRequest(request)
        headers = list(request_data.getHeaders())
        body = request[request_data.getBodyOffset():].tostring()
        return headers, body
    

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Send To 429 Bypasser", actionPerformed=lambda x: SwingUtilities.invokeLater(lambda: self.showOptionsDialog(invocation)))
        menu_list.add(menu_item)
        return menu_list

    def showOptionsDialog(self, invocation):
        # Create checkboxes for options
        add_headers_checkbox = JCheckBox("Add Custom Headers", True)
        change_user_agent_checkbox = JCheckBox("Change User Agent", True)
        using_capital_letters_checkbox = JCheckBox("Using Capital Letters", True)
        random_parameter_checkbox = JCheckBox("Using Random Parameter", True)
        HPP_checkbox = JCheckBox("Server-side HTTP Parameter Pollution", True) # HPP
        change_method_checkbox = JCheckBox("Change Method", True)
        route_alteration_checkbox = JCheckBox("The Route Alteration", True)
        AddNS_checkbox = JCheckBox("Adding Null Bytes, spaces and etc", True)
        Encoding_checkbox = JCheckBox("Encoding", True)

        # Text field for specifying parameter names
        laable= JLabel("Enter Specific Parameters (Optional)")
        parameter_text_field = JTextField(20)

        # Panel to contain checkboxes
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.add(add_headers_checkbox)
        panel.add(change_user_agent_checkbox)
        panel.add(using_capital_letters_checkbox)
        panel.add(random_parameter_checkbox)
        panel.add(HPP_checkbox)
        panel.add(change_method_checkbox)
        panel.add(route_alteration_checkbox)
        panel.add(Encoding_checkbox)
        panel.add(AddNS_checkbox)
        panel.add(laable)
        panel.add(parameter_text_field)  # Add the text field
        
        # Show options dialog
        result = JOptionPane.showConfirmDialog(None, panel, "Select Options", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        
        # If OK was clicked, process the request with selected options
        if result == JOptionPane.OK_OPTION:
            add_headers = add_headers_checkbox.isSelected()
            change_user_agent = change_user_agent_checkbox.isSelected()
            using_capital_letters = using_capital_letters_checkbox.isSelected()
            random_parameter = random_parameter_checkbox.isSelected()
            HttPP = HPP_checkbox.isSelected()
            change_method = change_method_checkbox.isSelected()
            route_alteration = route_alteration_checkbox.isSelected()
            AddNS = AddNS_checkbox.isSelected()
            Encoding = Encoding_checkbox.isSelected()
            params_to_modify = [param.strip() for param in parameter_text_field.getText().split(",")] if parameter_text_field.getText() else None
            threading.Thread(target=self.modify_and_send_request, args=(invocation, add_headers, change_user_agent, using_capital_letters, random_parameter, HttPP, change_method, route_alteration, Encoding, AddNS, params_to_modify)).start()

    def modify_and_send_request(self, invocation, add_headers, change_user_agent, using_capital_letters, random_parameter, HttPP, change_method, route_alteration, Encoding, AddNS, params_to_modify):
        selected_message = invocation.getSelectedMessages()[0]
        headers, body = self.getRequestHeadersAndBody(selected_message)
        headersp = headers
        bodyp = body
        path, url = self.getpath(selected_message)
        http_service = selected_message.getHttpService()
        # Modify headers if "Add Custom Headers" is selected
        if add_headers:
            for header in self.HEADERS_LIST:
                modified_headers = headers[:]  # Copy the headers
                modified_headers.append(header)

                # Build the modified request
                new_message = self._helpers.buildHttpMessage(modified_headers, body)

                # Send the modified request
                response = self._callbacks.makeHttpRequest(http_service, new_message)

                # Print the response status code
                status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                request_info = self._helpers.analyzeRequest(response)
                
                response_info = self._helpers.analyzeResponse(response.getResponse())
                response_headers = response_info.getHeaders()
                content_length1 = None
                
                for header in response_headers:
                    if header.lower().startswith("content-length:"):
                        content_length1 = int(header.split(":")[1].strip())
                        break
                # Extract the full URL and parse out the path and query string
                path1 = request_info.getUrl().getPath()
                query1 = request_info.getUrl().getQuery()

                if query1 is None:
                    url1 = path1
                else:
                    url1 = path1 + "?" + query1

                method1 = request_info.getMethod()
                host1 = response.getHttpService().getHost()
                # Log the request in the table with a placeholder for status code
                self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                self.messages.append(response)
                self.request_counter += 1
                
                #print("Sent request with header '{0}', received status: {1}".format(header, status_code))
        if change_user_agent:
            for agent in self.USER_AGENTS:
                # Change User-Agent if "Change User Agent" is selected
                modified_headers1 = headers[:]
                modified_headers1 = [h for h in modified_headers1 if not h.startswith("User-Agent:")]
                modified_headers1.append("User-Agent: " + agent)

                # Build the modified request
                new_message = self._helpers.buildHttpMessage(modified_headers1, body)

                # Send the modified request
                response = self._callbacks.makeHttpRequest(http_service, new_message)

                # Print the response status code
                status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                request_info = self._helpers.analyzeRequest(response)
                path1 = request_info.getUrl().getPath()
                query1 = request_info.getUrl().getQuery()

                response_info = self._helpers.analyzeResponse(response.getResponse())
                response_headers = response_info.getHeaders()
                content_length1 = None
                
                for header in response_headers:
                    if header.lower().startswith("content-length:"):
                        content_length1 = int(header.split(":")[1].strip())
                        break

                if query1 is None:
                    url1 = path1
                else:
                    url1 = path1 + "?" + query1
                method1 = request_info.getMethod()
                host1 = response.getHttpService().getHost()
                # Log the request in the table with a placeholder for status code
                self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                self.messages.append(response)
                self.request_counter += 1
                #print("Sent request with header '{0}', received status: {1}".format(agent, status_code))
                
        if using_capital_letters:
            num_variations = 10
            segments = path.strip('/').split('/')  # Split path by '/' and remove leading/trailing slashes
            variations = 0
            query_string = url.getQuery()  # Get existing query parameters

            while variations < num_variations:
                modified_segments = []
                for segment in segments:
                    # Randomly capitalize each character in the segment
                    modified_segment = ''.join(random.choice([c.upper(), c.lower()]) for c in segment)
                    modified_segments.append(modified_segment)
            
                # Reassemble the path with randomized segments and retain query parameters
                randomized_path = '/' + '/'.join(modified_segments)
                full_randomized_url = randomized_path + ("?{}".format(query_string) if query_string else "")

                new_url = URL(url.protocol, url.host, url.port, full_randomized_url)

                # Update the HTTP request line with the new URL
                headers, body = self.getRequestHeadersAndBody(selected_message)
                first_line = headers[0].split(" ")
                first_line[1] = new_url.getPath() + ("?{}".format(query_string) if query_string else "")  # Set path and query
                headers[0] = " ".join(first_line)
                
                # Build and send the modified request
                new_message = self._helpers.buildHttpMessage(headers, body)
                response = self._callbacks.makeHttpRequest(http_service, new_message)

                # Print the response status code for verification
                status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()

                request_info = self._helpers.analyzeRequest(response)
                path1 = request_info.getUrl().getPath()
                query1 = request_info.getUrl().getQuery()

                if query1 is None:
                    url1 = path1
                else:
                    url1 = path1 + "?" + query1
                method1 = request_info.getMethod()
                host1 = response.getHttpService().getHost()

                response_info = self._helpers.analyzeResponse(response.getResponse())
                response_headers = response_info.getHeaders()
                content_length1 = None
                
                for header in response_headers:
                    if header.lower().startswith("content-length:"):
                        content_length1 = int(header.split(":")[1].strip())
                        break
                
                # Log the request in the table with a placeholder for status code
                self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                self.messages.append(response)
                self.request_counter += 1
                #print("Sent request with new url '{0}', received status: {1}".format(new_url, status_code))
                variations += 1

        if random_parameter:
            # Generate a random value
            random_value = random.randint(1000, 9999)
            random_param = "random={}".format(random_value)
            #random_paramj = "\"random\"" + ":" + random_value
            # Determine the HTTP method (GET, POST, PUT, etc.)
            method = headersp[0].split(" ")[0].upper()
            content_type = self.getContentType(headersp)
            # Modify the request based on the method
            if method in ["POST", "PUT" , "PATCH"] and bodyp:
                if "application/x-www-form-urlencoded" in content_type:
                # Append the random parameter to the request body if it's a POST or PUT or PATCH with a body
                    modified_bodyp = bodyp + "&" + random_param
                    new_message = self._helpers.buildHttpMessage(headersp, modified_bodyp)
                    response = self._callbacks.makeHttpRequest(http_service, new_message)
                    # Print the response status code for verification
                    status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()

                    request_info = self._helpers.analyzeRequest(response)
                    path1 = request_info.getUrl().getPath()
                    query1 = request_info.getUrl().getQuery()

                    if query1 is None:
                        url1 = path1
                    else:
                        url1 = path1 + "?" + query1
                    method1 = request_info.getMethod()
                    host1 = response.getHttpService().getHost()

                    response_info = self._helpers.analyzeResponse(response.getResponse())
                    response_headers = response_info.getHeaders()
                    content_length1 = None
                    
                    for header in response_headers:
                        if header.lower().startswith("content-length:"):
                            content_length1 = int(header.split(":")[1].strip())
                            break
                    
                    # Log the request in the table with a placeholder for status code
                    self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                    self.messages.append(response)
                    self.request_counter += 1
                    #print("Sent request with Random Parameter received status: {0}".format(status_code))
                elif "application/json" in content_type:
                # Add random JSON parameter to the body if it's valid JSON
                    try:
                        # Parse the existing JSON body
                        json_bodyp = json.loads(bodyp)
                        
                        # Add a random parameter
                        random_key = "randomParam{}".format(random.randint(1000, 9999))
                        random_value = random.randint(1000, 9999)
                        json_bodyp[random_key] = random_value
                        
                        # Convert the modified JSON back to string
                        modified_bodyp = json.dumps(json_bodyp)
                        # Rebuild the request with modified body
                        new_message = self._helpers.buildHttpMessage(headersp, modified_bodyp)
                        response = self._callbacks.makeHttpRequest(http_service, new_message)
                        # Print the response status code for verification
                        status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                        request_info = self._helpers.analyzeRequest(response)
                        path1 = request_info.getUrl().getPath()
                        query1 = request_info.getUrl().getQuery()

                        if query1 is None:
                            url1 = path1
                        else:
                            url1 = path1 + "?" + query1
                        method1 = request_info.getMethod()
                        host1 = response.getHttpService().getHost()

                        response_info = self._helpers.analyzeResponse(response.getResponse())
                        response_headers = response_info.getHeaders()
                        content_length1 = None
                        
                        for header in response_headers:
                            if header.lower().startswith("content-length:"):
                                content_length1 = int(header.split(":")[1].strip())
                                break
                        
                        # Log the request in the table with a placeholder for status code
                        self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                        self.messages.append(response)
                        self.request_counter += 1
                        #print("Sent request with Random Parameter received status: {0}".format(status_code))
                    
                    except ValueError:
                        # If the body isn't valid JSON, print an error message
                        print("Error: Body is not valid JSON")
            
            else:
                
                # Append the random parameter to the URL if it's a GET request or if there's no body
                if "?" in url.toString():
                    new_url = URL("{}&{}".format(url, random_param))
                else:
                    new_url = URL("{}?{}".format(url, random_param))
                
                # Update the first line in headers with the modified URL
                headersp[0] = "{} {} {}".format(method, new_url.getPath() + "?" + new_url.getQuery(), headersp[0].split(" ")[2])
                new_message = self._helpers.buildHttpMessage(headersp, bodyp)
                response = self._callbacks.makeHttpRequest(http_service, new_message)
                # Print the response status code for verification
                status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                request_info = self._helpers.analyzeRequest(response)
                path1 = request_info.getUrl().getPath()
                query1 = request_info.getUrl().getQuery()

                if query1 is None:
                    url1 = path1
                else:
                    url1 = path1 + "?" + query1
                method1 = request_info.getMethod()
                host1 = response.getHttpService().getHost()

                response_info = self._helpers.analyzeResponse(response.getResponse())
                response_headers = response_info.getHeaders()
                content_length1 = None
                
                for header in response_headers:
                    if header.lower().startswith("content-length:"):
                        content_length1 = int(header.split(":")[1].strip())
                        break
                
                # Log the request in the table with a placeholder for status code
                self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                self.messages.append(response)
                self.request_counter += 1
                #print("Sent request with Random Parameter received status: {0}".format(status_code))
            
        if HttPP:
            
            headers, body = self.getRequestHeadersAndBody(selected_message)
            request_info = self._helpers.analyzeRequest(selected_message)
            url = request_info.getUrl()
            method = headers[0].split(" ")[0].upper()
            
            if method in ["GET", "HEAD", "OPTIONS"]:
                polluted_urls = self.generatePollutedUrls(url, params_to_modify=params_to_modify)
                for polluted_url in polluted_urls:
                    modified_headers = headers[:]
                    first_line = modified_headers[0].split(" ")
                    first_line[1] = polluted_url  # Set the path to the polluted URL
                    modified_headers[0] = " ".join(first_line)
                    
                    # Build and send the modified request
                    new_message = self._helpers.buildHttpMessage(modified_headers, body)
                    response = self._callbacks.makeHttpRequest(http_service, new_message)
                    
                    # Print the response status code for verification
                    status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                    request_info = self._helpers.analyzeRequest(response)
                    path1 = request_info.getUrl().getPath()
                    query1 = request_info.getUrl().getQuery()

                    if query1 is None:
                        url1 = path1
                    else:
                        url1 = path1 + "?" + query1
                    method1 = request_info.getMethod()
                    host1 = response.getHttpService().getHost()

                    response_info = self._helpers.analyzeResponse(response.getResponse())
                    response_headers = response_info.getHeaders()
                    content_length1 = None
                    
                    for header in response_headers:
                        if header.lower().startswith("content-length:"):
                            content_length1 = int(header.split(":")[1].strip())
                            break
                    
                    # Log the request in the table with a placeholder for status code
                    self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                    self.messages.append(response)
                    self.request_counter += 1
                    #print("Sent request for polluted URL '{0}', received status: {1}".format(polluted_url, status_code))

            elif method in ["POST", "PUT", "PATCH"]:
                content_type = self.getContentType(headersp)
                if "application/x-www-form-urlencoded" in content_type:
                    params = dict([param.split("=") for param in body.split("&")])
                    
                    # Iterate only through specified parameters
                    for param, value in params.items():
                        if params_to_modify and param not in params_to_modify:
                            continue  # Skip parameters not in the user-specified list

                        # Apply pollution logic for specified parameters
                        polluted_params1 = params.copy()
                        polluted_params1[param] = "{}&{}={}".format(value, param, value + "2")

                        polluted_body1 = "&".join(["{}={}".format(k, v) for k, v in polluted_params1.items()])
                        modified_headers = headers[:]
                        new_message1 = self._helpers.buildHttpMessage(modified_headers, polluted_body1)
                        response1 = self._callbacks.makeHttpRequest(http_service, new_message1)

                        # Print the response status for verification
                        status_code1 = self._helpers.analyzeResponse(response1.getResponse()).getStatusCode()
                        request_info = self._helpers.analyzeRequest(response1)
                        path1 = request_info.getUrl().getPath()
                        query1 = request_info.getUrl().getQuery()

                        if query1 is None:
                            url1 = path1
                        else:
                            url1 = path1 + "?" + query1
                        method1 = request_info.getMethod()
                        host1 = response1.getHttpService().getHost()

                        response_info = self._helpers.analyzeResponse(response1.getResponse())
                        response_headers = response_info.getHeaders()
                        content_length1 = None
                        
                        for header in response_headers:
                            if header.lower().startswith("content-length:"):
                                content_length1 = int(header.split(":")[1].strip())
                                break
                        
                        # Log the request in the table with a placeholder for status code
                        self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code1, content_length1])
                        self.messages.append(response1)
                        self.request_counter += 1
                        #print("Sent form-urlencoded polluted request with '{0}' original first, received status: {1}".format(param, status_code1))

                        polluted_params2 = params.copy()
                        polluted_params2[param] = "{}&{}={}".format(value + "2", param, value)

                        polluted_body2 = "&".join(["{}={}".format(k, v) for k, v in polluted_params2.items()])
                        new_message2 = self._helpers.buildHttpMessage(modified_headers, polluted_body2)
                        response2 = self._callbacks.makeHttpRequest(http_service, new_message2)

                        status_code2 = self._helpers.analyzeResponse(response2.getResponse()).getStatusCode()
                        request_info = self._helpers.analyzeRequest(response2)
                        path1 = request_info.getUrl().getPath()
                        query1 = request_info.getUrl().getQuery()

                        if query1 is None:
                            url1 = path1
                        else:
                            url1 = path1 + "?" + query1
                        method1 = request_info.getMethod()
                        host1 = response2.getHttpService().getHost()

                        response_info = self._helpers.analyzeResponse(response2.getResponse())
                        response_headers = response_info.getHeaders()
                        content_length2 = None
                        
                        for header in response_headers:
                            if header.lower().startswith("content-length:"):
                                content_length2 = int(header.split(":")[1].strip())
                                break
                        
                        # Log the request in the table with a placeholder for status code
                        self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code2, content_length2])
                        self.messages.append(response2)
                        self.request_counter += 1
                        #print("Sent form-urlencoded polluted request with '{0}' polluted first, received status: {1}".format(param, status_code2))

        if change_method:
            # Get the original HTTP method and URL
            original_method = headers[0].split(" ")[0].upper()
            request_info = self._helpers.analyzeRequest(selected_message)
            original_url = request_info.getUrl()
            original_query = original_url.getQuery()
            query_params = urlparse.parse_qs(original_query) if original_query else {}
            
            # Initialize modified headers and body
            modified_headers = headers[:]
            modified_body = body

            # Helper function to send the modified request
            def send_modified_request(modified_method, headers, body, content_type=None):
                # Update the request line with the new HTTP method and URL
                if modified_method in ["POST", "PUT", "PATCH"]:
                    headers[0] = "{} {} {}".format(modified_method, original_url.getPath(), headers[0].split(" ")[2])
                    
                    if content_type:
                        # Update or add Content-Type in headers
                        headers = [h for h in headers if not h.startswith("Content-Type:")]
                        headers.append("Content-Type: " + content_type)

                    # Build and send the modified request
                    new_message = self._helpers.buildHttpMessage(headers, body)
                    response = self._callbacks.makeHttpRequest(http_service, new_message)
                    status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                    request_info = self._helpers.analyzeRequest(response)
                    path1 = request_info.getUrl().getPath()
                    query1 = request_info.getUrl().getQuery()

                    if query1 is None:
                        url1 = path1
                    else:
                        url1 = path1 + "?" + query1
                    method1 = request_info.getMethod()
                    host1 = response.getHttpService().getHost()

                    response_info = self._helpers.analyzeResponse(response.getResponse())
                    response_headers = response_info.getHeaders()
                    content_length1 = None
                    
                    for header in response_headers:
                        if header.lower().startswith("content-length:"):
                            content_length1 = int(header.split(":")[1].strip())
                            break
                    
                    # Log the request in the table with a placeholder for status code
                    self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                    self.messages.append(response)
                    self.request_counter += 1
                    #print("Sent request with method '{0}', Content-Type '{1}', received status: {2}".format(modified_method, content_type, status_code))

                elif modified_method in ["GET"]:
                    headers[0] = "{}".format(modified_headers[0])

                    # Build and send the modified request
                    new_message = self._helpers.buildHttpMessage(headers, body)
                    response = self._callbacks.makeHttpRequest(http_service, new_message)
                    status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                    request_info = self._helpers.analyzeRequest(response)
                    path1 = request_info.getUrl().getPath()
                    query1 = request_info.getUrl().getQuery()

                    if query1 is None:
                        url1 = path1
                    else:
                        url1 = path1 + "?" + query1
                    method1 = request_info.getMethod()
                    host1 = response.getHttpService().getHost()

                    response_info = self._helpers.analyzeResponse(response.getResponse())
                    response_headers = response_info.getHeaders()
                    content_length1 = None
                    
                    for header in response_headers:
                        if header.lower().startswith("content-length:"):
                            content_length1 = int(header.split(":")[1].strip())
                            break
                    
                    # Log the request in the table with a placeholder for status code
                    self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                    self.messages.append(response)
                    self.request_counter += 1
                    #print("Sent request with method '{0}', Content-Type '{1}', received status: {2}".format(modified_method, content_type, status_code))
            
            # Switch method
            if original_method in ["GET", "HEAD", "OPTIONS"]:
                # Switching from GET/HEAD/OPTIONS to POST/PUT/PATCH
                for new_method in ["POST", "PUT", "PATCH"]:
                    # Convert URL query parameters to request body for form-urlencoded
                    if query_params:
                        form_body = "&".join(["{}={}".format(k, v[0]) for k, v in query_params.items()])
                        send_modified_request(new_method, modified_headers[:], form_body, "application/x-www-form-urlencoded")
                    
                    # Convert URL query parameters to JSON body
                    if query_params:
                        json_body = json.dumps({k: v[0] for k, v in query_params.items()})
                        send_modified_request(new_method, modified_headers[:], json_body, "application/json")

                    else:
                        form_body = "&".join(["{}={}".format(k, v[0]) for k, v in query_params.items()])
                        send_modified_request(new_method, modified_headers[:], form_body, "application/x-www-form-urlencoded")

            elif original_method in ["POST", "PUT", "PATCH"]:
                # Switching from POST/PUT/PATCH to GET/HEAD/OPTIONS
                new_method = "GET"  # Switching to GET as an example; you could also try HEAD or OPTIONS
                
                # Convert body parameters to URL query parameters if Content-Type is form-urlencoded
                if "application/x-www-form-urlencoded" in self.getContentType(headers):
                    try:
                        body_params = dict(param.split("=") for param in body.split("&"))
                        query_string = "&".join(["{}={}".format(k, v) for k, v in body_params.items()])
                        modified_url = "{}?{}".format(original_url.getPath(), query_string)
                        modified_headers[0] = "{} {} {}".format(new_method, modified_url, modified_headers[0].split(" ")[2])
                        send_modified_request(new_method, modified_headers[:], "", None)
                    except ValueError:
                        print("Error: Body is not valid")
                
                # Convert JSON body parameters to URL query parameters if Content-Type is application/json
                elif "application/json" in self.getContentType(headers):
                    try:
                        json_body = json.loads(body)
                        query_string = "&".join(["{}={}".format(k, v) for k, v in json_body.items()])
                        modified_url = "{}?{}".format(original_url.getPath(), query_string)
                        modified_headers[0] = "{} {} {}".format(new_method, modified_url, modified_headers[0].split(" ")[2])
                        send_modified_request(new_method, modified_headers[:], "", None)
                    except ValueError:
                        print("Error: Body is not valid JSON")

        if route_alteration:
            # Get the original request details
            headers, body = self.getRequestHeadersAndBody(selected_message)
            analyzed_request = self._helpers.analyzeRequest(selected_message)
            
            # Define the HTTP service from selected_message
            http_service = selected_message.getHttpService()
            
            # Modify the URL by appending "/.." to the path
            url = analyzed_request.getUrl()
            original_query = url.getQuery()  # Store the original query parameters
            modified_path = url.getPath().rstrip('/') + "/.."  # Ensures only one trailing "/.."
            modified_url = URL(url.getProtocol(), url.getHost(), url.getPort(), modified_path)
            
            # Update the first line of headers with the modified URL, preserving the original query if present
            modified_headers = list(headers)
            modified_request_line = "{} {} HTTP/1.1".format(
                analyzed_request.getMethod(),
                modified_url.getPath() + ("?" + original_query if original_query else "")
            )
            modified_headers[0] = modified_request_line
            
            # Build and send the modified request
            modified_request = self._helpers.buildHttpMessage(modified_headers, body)
            response = self._callbacks.makeHttpRequest(http_service, modified_request)
            
            # Analyze and print the status code from the response
            status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
            request_info = self._helpers.analyzeRequest(response)
            path1 = request_info.getUrl().getPath()
            query1 = request_info.getUrl().getQuery()

            if query1 is None:
                url1 = path1
            else:
                url1 = path1 + "?" + query1
            method1 = request_info.getMethod()
            host1 = response.getHttpService().getHost()

            response_info = self._helpers.analyzeResponse(response.getResponse())
            response_headers = response_info.getHeaders()
            content_length1 = None
                
            for header in response_headers:
                if header.lower().startswith("content-length:"):
                    content_length1 = int(header.split(":")[1].strip())
                    break
                    
            # Log the request in the table with a placeholder for status code
            self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
            self.messages.append(response)
            self.request_counter += 1
            #print("Sent request with modified path and preserved query, received status:", status_code)

        if AddNS:
            self.modify_body_with_null_bytes(http_service, headers, body, params_to_modify)

        if Encoding:
            # Determine if the request is GET or POST/PUT/PATCH
            is_body_request = body != ""  # If body is not empty, it indicates POST/PUT/PATCH
            
            def randomly_encode_chars(value, num_chars=3):
                """Randomly encodes a few characters in the value."""
                if len(value) == 0:
                    return value

                # Choose a random subset of indices to encode
                indices_to_encode = random.sample(range(len(value)), min(num_chars, len(value)))
                encoded_value = ''.join(
                    "%{0:02X}".format(ord(char)) if idx in indices_to_encode else char
                    for idx, char in enumerate(value)
                )
                return encoded_value

            if is_body_request:
                # Handle parameters in the body (POST, PUT, PATCH)
                content_type = self.getContentType(headers)
                
                if "application/json" in content_type:
                    try:
                        body_json = json.loads(body)
                        parameters = params_to_modify if params_to_modify else body_json.keys()
                        
                        for param in parameters:
                            if param in body_json:
                                original_value = str(body_json[param])
                                encoded_value = randomly_encode_chars(original_value)
                                modified_json = body_json.copy()
                                modified_json[param] = encoded_value
                                modified_body = json.dumps(modified_json)
                                modified_request = self._helpers.buildHttpMessage(headers, modified_body)
                                response = self._callbacks.makeHttpRequest(http_service, modified_request)
                                status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                                request_info = self._helpers.analyzeRequest(response)
                                path1 = request_info.getUrl().getPath()
                                query1 = request_info.getUrl().getQuery()

                                if query1 is None:
                                    url1 = path1
                                else:
                                    url1 = path1 + "?" + query1
                                method1 = request_info.getMethod()
                                host1 = response.getHttpService().getHost()

                                response_info = self._helpers.analyzeResponse(response.getResponse())
                                response_headers = response_info.getHeaders()
                                content_length1 = None
                                
                                for header in response_headers:
                                    if header.lower().startswith("content-length:"):
                                        content_length1 = int(header.split(":")[1].strip())
                                        break
                    
                                # Log the request in the table with a placeholder for status code
                                self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                                self.messages.append(response)
                                self.request_counter += 1
                                #print("Sent encoded body request, received status:", status_code)
                    except json.JSONDecodeError:
                        print("Invalid JSON body")

                elif "application/x-www-form-urlencoded" in content_type:
                    params = urlparse.parse_qs(body, keep_blank_values=True)
                    parameters = params_to_modify if params_to_modify else params.keys()
                    
                    for param in parameters:
                        if param in params:
                            original_value = params[param][0]
                            encoded_value = randomly_encode_chars(original_value)
                            modified_params = params.copy()
                            modified_params[param] = [encoded_value]
                            modified_body = "&".join("{}={}".format(k, v[0]) for k, v in modified_params.items())
                            modified_request = self._helpers.buildHttpMessage(headers, modified_body)
                            response = self._callbacks.makeHttpRequest(http_service, modified_request)
                            status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                            request_info = self._helpers.analyzeRequest(response)
                            path1 = request_info.getUrl().getPath()
                            query1 = request_info.getUrl().getQuery()

                            if query1 is None:
                                url1 = path1
                            else:
                                url1 = path1 + "?" + query1
                            method1 = request_info.getMethod()
                            host1 = response.getHttpService().getHost()

                            response_info = self._helpers.analyzeResponse(response.getResponse())
                            response_headers = response_info.getHeaders()
                            content_length1 = None
                            
                            for header in response_headers:
                                if header.lower().startswith("content-length:"):
                                    content_length1 = int(header.split(":")[1].strip())
                                    break
                    
                            # Log the request in the table with a placeholder for status code
                            self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                            self.messages.append(response)
                            self.request_counter += 1
                            #print("Sent encoded URL-form request, received status:", status_code)
            
            else:
                # Handle parameters in the URL (GET requests)
                parsed_url = urlparse.urlparse(str(url))
                query_params = urlparse.parse_qs(parsed_url.query)
                parameters = params_to_modify if params_to_modify else query_params.keys()
                
                # Loop through each parameter to modify one at a time
                for param in parameters:
                    if param in query_params:
                        original_value = query_params[param][0]
                        
                        # Encode only this parameter's value
                        encoded_value = randomly_encode_chars(original_value)
                        
                        # Copy all parameters but modify only the current one
                        modified_query_params = query_params.copy()
                        modified_query_params[param] = [encoded_value]
                        
                        # Reconstruct the modified query string
                        modified_query = "&".join("{}={}".format(k, v[0]) for k, v in modified_query_params.items())
                        
                        # Construct the modified path with only one encoded parameter
                        modified_path = "{}?{}".format(parsed_url.path, modified_query)
                        
                        # Update the request line in the headers
                        modified_headers = headers[:]
                        request_line = modified_headers[0]
                        method, _, http_version = request_line.split(" ")
                        modified_headers[0] = "{} {} {}".format(method, modified_path, http_version)
                        
                        # Send the modified request for this single-encoded parameter
                        modified_request = self._helpers.buildHttpMessage(modified_headers, None)
                        response = self._callbacks.makeHttpRequest(http_service, modified_request)
                        status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                        request_info = self._helpers.analyzeRequest(response)
                        path1 = request_info.getUrl().getPath()
                        query1 = request_info.getUrl().getQuery()

                        if query1 is None:
                            url1 = path1
                        else:
                            url1 = path1 + "?" + query1
                        method1 = request_info.getMethod()
                        host1 = response.getHttpService().getHost()

                        response_info = self._helpers.analyzeResponse(response.getResponse())
                        response_headers = response_info.getHeaders()
                        content_length1 = None
                        
                        for header in response_headers:
                            if header.lower().startswith("content-length:"):
                                content_length1 = int(header.split(":")[1].strip())
                                break
                    
                        # Log the request in the table with a placeholder for status code
                        self.log_table_model.addRow([self.request_counter, host1, method1, url1, status_code, content_length1])
                        self.messages.append(response)
                        self.request_counter += 1
                        #print("Sent request with only '{}' encoded, received status: {}".format(param, status_code))

        # Display the final response in Burp's UI
        selected_message.setResponse(response.getResponse())
