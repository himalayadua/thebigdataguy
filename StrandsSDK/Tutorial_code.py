"""
Cloud Task Analyzer Agent - Production Implementation
Part of the AWS Infrastructure Automation Pipeline using Strands Agents SDK

This module implements the Cloud Task Analyzer agent responsible for:
1. Analyzing sanitized AWS setup instructions
2. Identifying required AWS services
3. Enriching context with web search when needed
"""

import json
import logging
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

from ddgs import DDGS
from ddgs.exceptions import DDGSException, RatelimitException
from strands import Agent, tool
from pydantic import BaseModel, Field, validator


# ======================= Configuration =======================

class Config:
    """Centralized configuration for the Cloud Task Analyzer"""
    
    # Search configuration
    DEFAULT_REGION = "us-en"
    DEFAULT_MAX_RESULTS = 5
    MAX_RETRIES = 3
    RETRY_DELAY = 2.0  # seconds
    
    # AWS Services mapping
    AWS_SERVICE_KEYWORDS = {
    # Compute
    "virtual machine": ["EC2", "Lightsail"],
    "serverless function": ["Lambda"],
    "container orchestration": ["EKS", "ECS", "Fargate"],
    "managed container platform": ["App Runner", "Fargate", "Beanstalk", "ECS", "EKS"],
    "batch processing": ["Batch", "Lambda", "Fargate"],
    "simple web application": ["Lightsail", "Amplify", "Beanstalk", "EC2", "App Runner", "S3"],
    "static website hosting": ["S3", "CloudFront", "Amplify"],
    "high performance computing": ["ParallelCluster", "Batch", "EC2"],
    "edge computing": ["Outposts", "Wavelength", "Local Zones", "Lambda@Edge"],
    "application platform as a service (PaaS)": ["Beanstalk", "App Runner"],

    # Storage
    "object storage": ["S3"],
    "file storage": ["EFS", "FSx"],
    "block storage": ["EBS", "EC2 Instance Store"],
    "ephemeral storage": ["EC2 Instance Store"],
    "data archive": ["S3 Glacier"],
    "hybrid storage": ["Storage Gateway"],
    "data transfer": ["DataSync", "Snowball", "Snowcone", "Snowmobile", "Transfer Family"],
    "backup": ["Backup", "EBS Snapshots", "S3 Versioning"],

    # Database
    "relational database": ["RDS", "Aurora", "Redshift"],
    "nosql database": ["DynamoDB", "DocumentDB", "Keyspaces", "MemoryDB for Redis"],
    "in-memory cache": ["ElastiCache", "MemoryDB for Redis", "DynamoDB Accelerator (DAX)"],
    "data warehouse": ["Redshift"],
    "graph database": ["Neptune"],
    "time series database": ["Timestream"],
    "document database": ["DocumentDB", "DynamoDB"],
    "ledger database": ["QLDB"],
    "wide-column database": ["Keyspaces"],
    "database migration": ["DMS", "Schema Conversion Tool (SCT)"],

    # Networking & Content Delivery
    "virtual private cloud": ["VPC"],
    "load balancing": ["ELB", "Global Accelerator"],
    "dns & domain registration": ["Route 53"],
    "content delivery network (cdn)": ["CloudFront"],
    "dedicated network connection": ["Direct Connect"],
    "vpn": ["Client VPN", "Site-to-Site VPN"],
    "api management": ["API Gateway", "AppSync"],
    "service mesh": ["App Mesh"],
    "network firewall": ["Network Firewall"],
    "private network connectivity": ["PrivateLink"],

    # Machine Learning & AI
    "build train deploy ml": ["SageMaker"],
    "generative ai": ["Bedrock", "SageMaker JumpStart", "Amazon Q"],
    "image & video analysis": ["Rekognition"],
    "natural language processing (nlp)": ["Comprehend", "Lex", "Kendra", "Textract"],
    "text to speech": ["Polly"],
    "speech to text": ["Transcribe"],
    "translation": ["Translate"],
    "forecasting": ["Forecast"],
    "recommendations": ["Personalize"],
    "ai coding companion": ["CodeWhisperer", "Amazon Q"],
    "document analysis & ocr": ["Textract"],
    "intelligent search": ["Kendra"],
    "fraud detection": ["Fraud Detector"],
    "automated code review": ["CodeGuru"],

    # Analytics
    "interactive query": ["Athena"],
    "big data processing": ["EMR", "Glue"],
    "data streaming": ["Kinesis", "Managed Streaming for Kafka (MSK)"],
    "etl & data integration": ["Glue", "DataSync", "Data Pipeline"],
    "business intelligence (bi)": ["QuickSight"],
    "log analytics": ["OpenSearch Service", "CloudWatch Logs Insights"],
    "data lake management": ["Lake Formation"],
    "data pipeline orchestration": ["Managed Workflows for Apache Airflow (MWAA)", "Step Functions"],

    # Security, Identity, & Compliance
    "identity & access management": ["IAM", "IAM Identity Center"],
    "user authentication & authorization": ["Cognito", "IAM"],
    "single sign-on (sso)": ["IAM Identity Center"],
    "encryption key management": ["KMS", "CloudHSM"],
    "secrets management": ["Secrets Manager", "Parameter Store"],
    "web application firewall": ["WAF"],
    "ddos protection": ["Shield"],
    "threat detection": ["GuardDuty", "Inspector", "Macie"],
    "compliance & auditing": ["Security Hub", "Config", "Audit Manager", "CloudTrail"],
    "data protection & privacy": ["Macie"],
    "vulnerability management": ["Inspector"],
    "certificate management": ["Certificate Manager (ACM)"],
    "directory service": ["Directory Service"],

    # DevOps & Developer Tools
    "infrastructure as code (iac)": ["CloudFormation", "CDK", "SAM"],
    "source control": ["CodeCommit"],
    "ci/cd pipeline": ["CodePipeline", "CodeBuild", "CodeDeploy", "CodeStar"],
    "container registry": ["ECR"],
    "monitoring & observability": ["CloudWatch", "X-Ray", "Managed Service for Prometheus", "Managed Grafana"],
    "logging & tracing": ["CloudTrail", "CloudWatch Logs", "X-Ray"],
    "systems management & automation": ["Systems Manager", "OpsWorks"],
    "cloud ide": ["Cloud9"],
    "artifact repository": ["CodeArtifact"],
    "command line interface (cli)": ["AWS CLI"],
    "application performance monitoring (apm)": ["X-Ray"],

    # Application Integration
    "message queue": ["SQS"],
    "notifications & pub/sub": ["SNS"],
    "application orchestration & workflow": ["Step Functions", "Managed Workflows for Apache Airflow (MWAA)"],
    "event bus": ["EventBridge"],
    "managed message broker": ["MQ"],
    "graphql api": ["AppSync"],

    # Management & Governance
    "cloud financial management": ["Cost Explorer", "Budgets", "Cost and Usage Report (CUR)"],
    "centralized management & governance": ["Organizations", "Control Tower", "Service Catalog"],
    "resource configuration tracking": ["Config"],
    "health monitoring": ["Health Dashboard", "Personal Health Dashboard"],

    # End-User Computing
    "virtual desktop": ["WorkSpaces"],
    "application streaming": ["AppStream 2.0"],

    # Internet of Things (IoT)
    "iot device connectivity & management": ["IoT Core"],
    "iot data processing": ["IoT Analytics", "IoT Events"],
    "iot on the edge": ["Greengrass"],
    }
    
    # Logging
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


# ======================= Logging Setup =======================

def setup_logging(name: str = __name__) -> logging.Logger:
    """Configure structured logging for production use"""
    logger = logging.getLogger(name)
    logger.setLevel(Config.LOG_LEVEL)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(Config.LOG_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


logger = setup_logging("cloud_task_analyzer")
strands_logger = logging.getLogger("strands")
strands_logger.setLevel(Config.LOG_LEVEL)


# ======================= Data Models =======================

class TaskType(Enum):
    """Enumeration of supported AWS task types"""
    DEPLOY = "deploy"
    CONFIGURE = "configure"
    SETUP = "setup"
    CREATE = "create"
    MIGRATE = "migrate"
    OPTIMIZE = "optimize"
    MONITOR = "monitor"
    SECURE = "secure"


class SearchResult(BaseModel):
    """Structured search result model"""
    title: str
    body: str
    href: Optional[str] = None
    relevance_score: Optional[float] = Field(None, ge=0.0, le=1.0)


class AnalysisResult(BaseModel):
    """Structured output from the Cloud Task Analyzer"""
    request_id: str
    timestamp: str
    task_description: str
    task_type: TaskType
    identified_services: List[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    additional_context: Optional[Dict[str, Any]] = None
    search_performed: bool = False
    errors: List[str] = Field(default_factory=list)
    
    @validator('identified_services')
    def validate_services(cls, v):
        """Ensure services are valid AWS service names"""
        valid_services = set()
        for service_list in Config.AWS_SERVICE_KEYWORDS.values():
            valid_services.update(service_list)
        
        # Add more comprehensive AWS service list in production
        valid_services.update([
            "EC2", "S3", "Lambda", "RDS", "DynamoDB", "CloudFormation",
            "CloudWatch", "IAM", "VPC", "ECS", "EKS", "SQS", "SNS"
        ])
        
        return [s for s in v if s in valid_services]


# ======================= Web Search Tool =======================

class WebSearchManager:
    """Manages web search operations with retry logic and rate limiting"""
    
    def __init__(self):
        self.ddgs = DDGS()
        self.last_search_time = 0
        self.min_interval = 1.0  # Minimum seconds between searches
    
    def _rate_limit(self):
        """Implement rate limiting to avoid hitting API limits"""
        current_time = time.time()
        elapsed = current_time - self.last_search_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_search_time = time.time()
    
    def search_with_retry(
        self,
        keywords: str,
        region: str = Config.DEFAULT_REGION,
        max_results: Optional[int] = Config.DEFAULT_MAX_RESULTS,
        max_retries: int = Config.MAX_RETRIES
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Perform web search with automatic retry on rate limiting
        
        Args:
            keywords: Search query terms
            region: Search region code
            max_results: Maximum number of results to return
            max_retries: Maximum number of retry attempts
            
        Returns:
            List of search results or error message
        """
        for attempt in range(max_retries):
            try:
                self._rate_limit()
                results = self.ddgs.text(
                    keywords=keywords,
                    region=region,
                    max_results=max_results
                )
                
                if results:
                    logger.info(f"Search successful for: {keywords[:50]}...")
                    return list(results)
                else:
                    logger.warning(f"No results found for: {keywords[:50]}...")
                    return []
                    
            except RatelimitException as e:
                wait_time = Config.RETRY_DELAY * (2 ** attempt)
                logger.warning(
                    f"Rate limit hit (attempt {attempt + 1}/{max_retries}). "
                    f"Waiting {wait_time}s..."
                )
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                else:
                    return f"Rate limit exceeded after {max_retries} attempts"
                    
            except DDGSException as e:
                logger.error(f"DuckDuckGo search error: {e}")
                return f"Search service error: {str(e)}"
                
            except Exception as e:
                logger.exception(f"Unexpected error during search: {e}")
                return f"Unexpected error: {str(e)}"
        
        return "Maximum retry attempts exceeded"


# Initialize global search manager
search_manager = WebSearchManager()


@tool
def websearch(
    keywords: str,
    region: str = Config.DEFAULT_REGION,
    max_results: Optional[int] = Config.DEFAULT_MAX_RESULTS
) -> str:
    """
    Search the web to get updated information about AWS services and cloud infrastructure.
    
    Args:
        keywords: Search query terms (e.g., "AWS S3 static website hosting best practices")
        region: Search region for localized results (default: "us-en")
        max_results: Maximum number of results to return (default: 5)
    
    Returns:
        JSON string containing search results or error message
    """
    try:
        # Input validation
        if not keywords or not keywords.strip():
            return json.dumps({"error": "Keywords cannot be empty"})
        
        if len(keywords) > 500:
            keywords = keywords[:500]
            logger.warning("Keywords truncated to 500 characters")
        
        # Perform search
        results = search_manager.search_with_retry(
            keywords=keywords.strip(),
            region=region,
            max_results=max_results
        )
        
        # Format results
        if isinstance(results, str):  # Error message
            return json.dumps({"error": results})
        elif isinstance(results, list):
            formatted_results = []
            for r in results[:max_results] if max_results else results:
                formatted_results.append({
                    "title": r.get("title", ""),
                    "body": r.get("body", "")[:500],  # Truncate long descriptions
                    "href": r.get("href", "")
                })
            return json.dumps({
                "success": True,
                "count": len(formatted_results),
                "results": formatted_results
            })
        else:
            return json.dumps({"error": "No results found"})
            
    except Exception as e:
        logger.exception(f"Error in websearch tool: {e}")
        return json.dumps({"error": f"Search failed: {str(e)}"})


# ======================= Cloud Task Analyzer Agent =======================

class CloudTaskAnalyzer:
    """Production-ready Cloud Task Analyzer with enhanced capabilities"""
    
    SYSTEM_PROMPT = """You are the Cloud Task Analyzer, a specialized AWS infrastructure expert agent.

Your responsibilities:
1. Analyze sanitized AWS setup instructions to identify required services
2. Determine the task type and complexity
3. Map instructions to specific AWS services
4. Use web search to gather current best practices when needed
5. Provide structured, actionable analysis

Guidelines:
- Focus on AWS services and cloud infrastructure patterns
- Prioritize security and cost-effectiveness in your recommendations
- Use web search for:
  * Current AWS service limits and pricing
  * Best practices for specific use cases
  * Recent AWS feature updates
  * Compliance and security requirements
- Always validate service compatibility
- Consider scalability and maintainability

Output Format:
Provide a clear, structured response identifying:
- Main task objective
- Required AWS services (in order of importance)
- Key considerations (security, cost, performance)
- Any potential risks or limitations

Remember: You're analyzing PRE-VALIDATED instructions. Focus on technical implementation details."""
    
    def __init__(self):
        """Initialize the Cloud Task Analyzer agent"""
        self.agent = Agent(
            name="CloudTaskAnalyzer",
            system_prompt=self.SYSTEM_PROMPT,
            tools=[websearch],
            temperature=0.3,  # Lower temperature for more consistent analysis
        )
        self.request_counter = 0
        logger.info("Cloud Task Analyzer agent initialized")
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID for tracking"""
        self.request_counter += 1
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"CTA-{timestamp}-{self.request_counter:04d}"
    
    def _identify_task_type(self, instruction: str) -> TaskType:
        """Identify the type of task from the instruction"""
        instruction_lower = instruction.lower()
        
        task_keywords = {
            TaskType.DEPLOY: ["deploy", "launch", "release"],
            TaskType.SETUP: ["setup", "install", "initialize"],
            TaskType.CREATE: ["create", "build", "establish"],
            TaskType.CONFIGURE: ["configure", "config", "set up"],
            TaskType.MIGRATE: ["migrate", "transfer", "move"],
            TaskType.OPTIMIZE: ["optimize", "improve", "enhance"],
            TaskType.MONITOR: ["monitor", "track", "observe"],
            TaskType.SECURE: ["secure", "protect", "harden"],
        }
        
        for task_type, keywords in task_keywords.items():
            if any(keyword in instruction_lower for keyword in keywords):
                return task_type
        
        return TaskType.SETUP  # Default
    
    def _extract_services(self, response: str, instruction: str) -> List[str]:
        """Extract AWS services from agent response and instruction context"""
        services = set()
        
        # Check instruction against known patterns
        instruction_lower = instruction.lower()
        for pattern, service_list in Config.AWS_SERVICE_KEYWORDS.items():
            if pattern in instruction_lower:
                services.update(service_list)
        
        # Extract services mentioned in agent response
        response_upper = response.upper()
        all_possible_services = set()
        for service_list in Config.AWS_SERVICE_KEYWORDS.values():
            all_possible_services.update(service_list)
        
        for service in all_possible_services:
            if service.upper() in response_upper:
                services.add(service)
        
        return sorted(list(services))
    
    def analyze(self, instruction: str) -> AnalysisResult:
        """
        Analyze sanitized AWS setup instruction
        
        Args:
            instruction: Pre-validated, sanitized instruction text
            
        Returns:
            AnalysisResult object with structured analysis
        """
        request_id = self._generate_request_id()
        logger.info(f"Processing request {request_id}: {instruction[:100]}...")
        
        try:
            # Enhance instruction with context
            enhanced_prompt = f"""Analyze this AWS infrastructure task: "{instruction}"
            
            Consider:
            1. What AWS services are specifically needed?
            2. Are there any recent AWS updates or best practices to consider?
            3. What are the security implications?
            
            Provide a comprehensive analysis."""
            
            # Get agent analysis
            response = self.agent(enhanced_prompt)
            
            # Parse response
            task_type = self._identify_task_type(instruction)
            services = self._extract_services(str(response), instruction)
            
            # Determine if search was used (check agent's tool usage)
            search_performed = "search" in str(response).lower() or "found" in str(response).lower()
            
            # Calculate confidence based on service match
            confidence = min(1.0, len(services) * 0.2 + 0.4)
            
            result = AnalysisResult(
                request_id=request_id,
                timestamp=datetime.utcnow().isoformat(),
                task_description=instruction,
                task_type=task_type,
                identified_services=services,
                confidence_score=confidence,
                search_performed=search_performed,
                additional_context={
                    "agent_response": str(response)[:1000],
                    "analysis_version": "1.0.0"
                }
            )
            
            logger.info(f"Request {request_id} completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error processing request {request_id}: {e}")
            return AnalysisResult(
                request_id=request_id,
                timestamp=datetime.utcnow().isoformat(),
                task_description=instruction,
                task_type=TaskType.SETUP,
                identified_services=[],
                confidence_score=0.0,
                errors=[str(e)]
            )


# ======================= Main Entry Point =======================

def main():
    """Main entry point for demonstration"""
    
    # Initialize analyzer
    analyzer = CloudTaskAnalyzer()
    
    # Example test cases
    test_cases = [
        "Deploy a static website",
        "Setup a serverless API with authentication",
        "Create a multi-tier web application with database",
        "Configure auto-scaling for EC2 instances",
        "Migrate on-premise database to AWS"
    ]
    
    print("=" * 60)
    print("Cloud Task Analyzer - Production Demo")
    print("=" * 60)
    
    for instruction in test_cases:
        print(f"\n📋 Instruction: {instruction}")
        print("-" * 40)
        
        result = analyzer.analyze(instruction)
        
        print(f"✅ Task Type: {result.task_type.value}")
        print(f"🔧 Services: {', '.join(result.identified_services)}")
        print(f"📊 Confidence: {result.confidence_score:.1%}")
        print(f"🔍 Web Search Used: {result.search_performed}")
        
        if result.errors:
            print(f"❌ Errors: {', '.join(result.errors)}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()