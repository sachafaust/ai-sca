# AI-Powered SCA Vulnerability Scanner

A Software Composition Analysis (SCA) scanner designed with an **AI Agent First** philosophy, leveraging AI models for bulk vulnerability analysis instead of traditional sequential API calls.

## 📋 PDR + AI Agent Methodology

This project pioneered a new approach to AI-first software development using complementary files:

### Product Design Requirements (PDR)
- **File**: `Main-SCA-Scanner-PDR.md`
- **Purpose**: Defines **WHAT** to build
- **Content**: Comprehensive technical specifications, architecture, requirements, and design decisions
- **Audience**: Engineers, stakeholders, and AI agents who need to understand the complete system design

### AI Agent Implementation Guidance

#### For Claude Code (claude.ai/code)
- **File**: `CLAUDE.md`
- **Purpose**: Claude-specific mental model and implementation framework
- **Content**: PDR-first philosophy, TDD workflow, engineering principles tailored for Claude
- **Usage**: Automatically loaded when using Claude Code

#### For Other AI Coding Agents
- **File**: `build.prompt`
- **Purpose**: Universal engineering directives for any AI coding agent
- **Content**: Core tenets, TDD approach, implementation standards
- **Usage**: Provide as initial prompt to ChatGPT, Cursor, Copilot, etc.

### Why This Approach Works

**Traditional Development:**
```
Requirements Doc → Human Engineers → Implementation
```

**AI-First Development:**
```
PDR (What) + AI Agent Guidance (How) → AI Coding Agent → Implementation
                    ├── CLAUDE.md (for Claude Code)
                    └── build.prompt (for other AI agents)
```

### Benefits

1. **Separation of Concerns**: Project-specific requirements separate from universal engineering practices
2. **Consistency**: Every AI coding agent gets the same high-quality engineering mindset
3. **Scalability**: One build prompt template works across all projects
4. **Quality**: Ensures every project follows best practices
5. **Flexibility**: Different AI agents get optimized guidance (Claude vs others)

## 🏗️ File Structure

```
SCA/
├── README.md                # This file - project and methodology overview
├── Main-SCA-Scanner-PDR.md  # PDR - comprehensive design requirements
├── CLAUDE.md                # Claude Code specific framework
└── build.prompt             # Universal AI agent engineering directives
```

### File Purposes

- **README.md**: Human-readable overview of project and methodology
- **Main-SCA-Scanner-PDR.md**: Complete technical specification for the scanner
- **CLAUDE.md**: AI agent implementation framework with TDD workflow and engineering principles

## 🤖 AI Coding Agent Implementation

The AI coding agent receives:

1. **Engineering Identity**: World-class full-stack engineer with creativity, perseverance, and expertise
2. **Core Principles**: 
   - Only make new mistakes (learn and apply broadly)
   - Future-proof through comprehensive testing
   - Token frugality with cost reasoning
   - Continuous improvement mindset
3. **Specific Task**: Implement according to the PDR
4. **Success Criteria**: Performance, cost, accuracy, and AI readiness metrics

## 🔧 Usage

### For This Project
```bash
# AI Coding Agent reads both files:
# 1. Main-SCA-Scanner-PDR.md - understand WHAT to build
# 2. CLAUDE.md - understand HOW to approach building

# AI Coding Agent then implements the complete scanner according to specifications
```

### For Other Projects
```bash
# Copy CLAUDE.md framework to any project directory
# Create project-specific PDR
# AI Coding Agent implements using same high-quality approach
```

## 📊 Expected Outcomes

### Performance Targets
- **Speed**: <30 minutes for 1000+ dependencies
- **Cost**: <$0.75 per 1000 packages analyzed
- **Accuracy**: 95%+ vulnerability detection rate
- **AI Agent Ready**: 90%+ automated processing capability

### Technical Implementation
- Multi-language dependency parsing (Python, JavaScript, Docker)
- AI provider integration (OpenAI, Anthropic, Google, X AI)
- Live search capabilities for current vulnerability data
- Comprehensive test suite with 90%+ coverage
- Structured JSON output for AI agent consumption

## 🌟 Methodology Adoption

This PDR + CLAUDE.md approach can be adopted for any software project:

1. **Create PDR**: Define your project's specific requirements, architecture, and design decisions
2. **Adapt CLAUDE.md**: Use the AI agent implementation framework with project-specific customizations
3. **Customize Implementation Task**: Update the task section to reference your PDR
4. **Deploy AI Coding Agent**: Let the AI coding agent implement according to both specifications

### Template Structure
```
YourProject/
├── README.md              # Project overview and methodology explanation
├── YourProject-PDR.md     # Project-specific design requirements
└── CLAUDE.md              # AI agent framework adapted for your project
```

## 🚀 Future Vision

This methodology represents a paradigm shift toward AI-first software development:

- **PDRs** become the new specification format optimized for AI comprehension
- **CLAUDE.md** becomes a universal AI agent implementation framework
- **AI Coding Agents** become the primary implementation workforce
- **Humans** focus on design, requirements, and oversight

The combination creates a scalable, consistent approach to building high-quality software with AI coding agents while maintaining engineering excellence and best practices.

## 📖 Related Concepts

- **AI Agent First**: Design everything for autonomous AI agent operation
- **Context Window Optimization**: Leverage AI capabilities for massive parallel processing
- **Separation of Concerns**: What to build vs How to build
- **Universal Engineering Patterns**: Reusable quality standards across projects