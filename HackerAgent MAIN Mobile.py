import langchain
from langchain.llms.ollama import Ollama
from langchain_core.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain_community.document_loaders import DirectoryLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings, OpenAI, ChatOpenAI
from langchain.embeddings.llamacpp import LlamaCppEmbeddings
from langchain.llms.llamacpp import LlamaCpp
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader
from langchain.tools.retriever import create_retriever_tool
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain.utilities.python import PythonREPL
import getpass, socket, sys, subprocess, platform, os, multiprocessing, psutil, io
from typing import Any, Dict, List, Optional, Type, Union
from pydantic import BaseModel, Field, Extra
from langchain.tools import BaseTool
from playwright.sync_api import sync_playwright, Page, Response, Browser
from langchain_core.callbacks.base import BaseCallbackHandler

os.environ["LANGCHAIN_TRACING_V2"] = "True"
os.environ["LANGCHAIN_API_KEY"] = "ls__18fd3bc1dc4146629d6831e0c0fd9ad8"

# WORKFLOW #############################################################################

# user hack prompt > | llm > tools > documents > history | > llm output

# components: 
# -function calling, document reading, and planning
# -Playwright browser testing library *
# -terminal, python repl *
# -RAG retrieval with kali linux usage documentation *

# Document details:
# "These documents include a document on general web hacking, two documents on SQL injections, two documents on XSS, and a document on SSRF"

# vuln types:	
#LFI		
#Executing files present on the server’s website via unchecked user input.

#CSRF		
#Tricking a user into submitting a malicious request to a web application where they are authenticated.

#XSS		
#Injection of a malicious script into an otherwise trusted website.

#SQL 		
#Insertion of malicious SQL code into a database query, allowing attackers to manipulate or gain unauthorized access to the database.

#Brute Force		
#Submitting numerous combinations of usernames and passwords to the login page until the correct credentials are discovered.

#SQL Union		
#Insertion of SQL code into a database query with the SQL UNION operator, allowing an attacker to retrieve data from different database tables.

#SSTI		
#Injection of malicious code into a server-side template engine.

#Webhook XSS		
#Use of an <img> tag XSS attack to send to an admin to exfiltrate their document.innerhtml (which contains a secret) to a webhook.

#File upload		
#Uploading script files (php files) to a website in place of image files (JPEG/PNG) by spoofing the content header.

#Authorization bypass		
#Interception of requests, stealing session tokens, and modifying hidden elements to act as an administrator.

#SSRF		
#Accessing an administrator endpoint by bypassing input filters.

#Javascript attacks		
#Injecting malicious scripts into web pages viewed by other users and manipulating JavaScript source code to steal information or manipulate actions.

#Hard SQL injection		
#SQL injection attack with an unusual payload.

#Hard SQL union		
#Performing a SQL union attack when the server does not return errors to the attacker.

#XSS + CSRF		
#Use of an <img> tag XSS attack to send to an admin to create a password change on their behalf, allowing the user to login with the admin’s newly changed password.


#RETRIEVER + MEMORY STORE
########################################################################################

#TOOLS
########################################################################################

class SubprocessTool(BaseTool):
    name = "subprocess"
    description = "Execute a command in a subprocess and return the output"

    def _run(self, tool_input: Union[str, Dict]) -> str:
        if isinstance(tool_input, dict):
            command = tool_input["command"]
        else:
            command = tool_input

        try:
            output = subprocess.check_output(command, shell=True, universal_newlines=True)
            return output.strip()
        except subprocess.CalledProcessError as e:
            return f"Error: {e}"

    async def _arun(self, tool_input: Union[str, Dict]) -> str:
        raise NotImplementedError("SubprocessTool does not support async")

class PlaywrightTool(BaseTool):
    name = "playwright"
    description = "Interact with a sandboxed website using Playwright for cybersecurity testing"

    def __init__(self):
        super().__init__()
        self.browser: Browser = sync_playwright().start().chromium.launch(headless=False)
        self.page: Page = self.browser.new_page()

    def _run(self, tool_input: Union[str, Dict]) -> str:
        if isinstance(tool_input, dict):
            action = tool_input["action"]
            url = tool_input.get("url", "")
            selector = tool_input.get("selector", "")
            value = tool_input.get("value", "")
        else:
            raise ValueError("Input must be a dictionary")

        try:
            if action == "navigate":
                self.page.goto(url)
                return f"Navigated to {url}"
            elif action == "click":
                self.page.click(selector)
                return f"Clicked on element: {selector}"
            elif action == "type":
                self.page.type(selector, value)
                return f"Typed '{value}' into element: {selector}"
            elif action == "get_text":
                text = self.page.inner_text(selector)
                return f"Text content of element '{selector}': {text}"
            elif action == "check_exists":
                exists = self.page.query_selector(selector) is not None
                return f"Element '{selector}' exists: {exists}"
            elif action == "close":
                self.browser.close()
                return "Closed the browser"
            else:
                return f"Unknown action: {action}"
        except Exception as e:
            return f"Error: {str(e)}"

    async def _arun(self, tool_input: Union[str, Dict]) -> str:
        raise NotImplementedError("PlaywrightTool does not support async")

    def __del__(self):
        if self.browser:
            self.browser.close()
    
class PythonExecInput(BaseModel):
    code: str = Field(description="The Python code to execute")

class PythonExecTool(BaseTool):
    name = "python_exec"
    description = "Execute arbitrary Python code"
    args_schema: Type[BaseModel] = PythonExecInput

    def _run(self, tool_input: PythonExecInput) -> str:
        # Redirect stdout to a buffer
        buffer = io.StringIO()
        sys.stdout = buffer

        try:
            # Execute the Python code
            exec(tool_input.code)
            output = buffer.getvalue()
        except Exception as e:
            output = f"Error: {str(e)}"
        finally:
            # Restore stdout
            sys.stdout = sys.__stdout__

        return output

    async def _arun(self, tool_input: PythonExecInput) -> str:
        raise NotImplementedError("PythonExecTool does not support async")
    
subprocess_tool = SubprocessTool()
python_exec_tool = PythonExecTool()
playwright_tool = PlaywrightTool()


tools = [
    subprocess_tool,
    python_exec_tool,
    playwright_tool,
]


#LLM INITIALIATION
########################################################################################

#llm = Ollama(model="llama3")
#llm = LlamaCpp(model_path=r"C:\Users\m1cr0\.cache\lm-studio\models\lmstudio-community\Meta-Llama-3-8B-Instruct-GGUF\Meta-Llama-3-8B-Instruct-Q4_K_M.gguf")
llm = Ollama(model="phi3")
llm_with_tools = llm.bind_tools(tools)

#PROMPT CREATION
########################################################################################

username = getpass.getuser()
current_working_directory = os.getcwd()
operating_system = platform.system()

# Additional system and network information
host_name = socket.gethostname()
try:
    ip_address = socket.gethostbyname(host_name)
except socket.gaierror:
    ip_address = "Unavailable"
architecture = platform.machine()
processor = platform.processor()
cpu_count = multiprocessing.cpu_count()
total_memory = psutil.virtual_memory().total / (1024**3)  # Convert from bytes to GB
python_version = sys.version

prompt_template = """

You are a helpful cybersecurity assistant

chat_history:
{chat_history}

user_system_details:
Name: {username}
CWD: {current_working_directory}
OS: {operating_system}
Host Name: {host_name}
IP Address: {ip_address}
Architecture: {architecture}
Processor: {processor}
CPU Count: {cpu_count}
Total Memory: {total_memory:.2f} GB
Python Version: {python_version}

human:
{input}

system:
{agent_scratchpad}
"""



prompt = PromptTemplate(
    input_variables=["chat_history", "username", "current_working_directory", "operating_system", "host_name", "ip_address", "architecture", "processor", "cpu_count", "total_memory:.2f", "python_version", "input", "agent_scratchpad"], template=prompt_template
)

#AGENT CREATION AND EXECUTION
########################################################################################

agent = create_tool_calling_agent(llm_with_tools, tools, prompt)

agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

while True:
    user_input = input("Enter your input (or 'quit' to exit): ")
    
    if user_input.lower() == 'quit':
        break

    result = agent_executor.invoke(
    {
        "input": user_input,
        "chat_history": [],
        "username": username,
        "current_working_directory": current_working_directory,
        "operating_system": operating_system,
        "host_name": host_name,
        "ip_address": ip_address,
        "architecture": architecture,
        "processor": processor,
        "cpu_count": cpu_count,
        "total_memory": total_memory,
        "python_version": python_version,
        "agent_scratchpad": ""
    }
)
    
    print(result)
