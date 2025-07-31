<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Script Execution Guide</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1a2332 50%, #2d3748 100%);
            color: #e2e8f0;
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
            padding: 3rem 0;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 16px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        h1 {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa, #a78bfa, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
            letter-spacing: -0.02em;
        }

        .subtitle {
            font-size: 1.25rem;
            color: #94a3b8;
            font-weight: 400;
            max-width: 600px;
            margin: 0 auto;
        }

        .toc {
            background: rgba(30, 41, 59, 0.7);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 3rem;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        .toc h2 {
            color: #f1f5f9;
            font-size: 1.5rem;
            margin-bottom: 1rem;
            font-weight: 600;
        }

        .toc ul {
            list-style: none;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 0.5rem;
        }

        .toc a {
            color: #60a5fa;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            transition: all 0.2s ease;
            display: block;
        }

        .toc a:hover {
            background: rgba(96, 165, 250, 0.1);
            color: #93c5fd;
        }

        .section {
            margin-bottom: 4rem;
            background: rgba(30, 41, 59, 0.4);
            border-radius: 16px;
            padding: 2.5rem;
            border: 1px solid rgba(148, 163, 184, 0.15);
            backdrop-filter: blur(8px);
        }

        .section h2 {
            font-size: 2rem;
            color: #f1f5f9;
            margin-bottom: 2rem;
            font-weight: 600;
            position: relative;
            padding-bottom: 0.5rem;
        }

        .section h2:after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 60px;
            height: 3px;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            border-radius: 2px;
        }

        .subsection {
            margin-bottom: 2.5rem;
            background: rgba(15, 23, 42, 0.6);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid rgba(100, 116, 139, 0.2);
        }

        .subsection h3 {
            font-size: 1.25rem;
            color: #cbd5e1;
            margin-bottom: 1rem;
            font-weight: 600;
        }

        .info-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
            background: rgba(15, 23, 42, 0.8);
            border-radius: 8px;
            overflow: hidden;
        }

        .info-table th,
        .info-table td {
            padding: 1rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid rgba(100, 116, 139, 0.2);
        }

        .info-table th {
            background: rgba(30, 41, 59, 0.8);
            color: #f1f5f9;
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .info-table td {
            color: #cbd5e1;
        }

        .info-table tr:last-child td {
            border-bottom: none;
        }

        pre {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 1.5rem;
            overflow-x: auto;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
            position: relative;
        }

        code {
            color: #94a3b8;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
        }

        .powershell code {
            color: #60a5fa;
        }

        .bash code {
            color: #34d399;
        }

        .code-label {
            position: absolute;
            top: 0.5rem;
            right: 1rem;
            font-size: 0.75rem;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 500;
            letter-spacing: 0.1em;
        }

        .highlight-box {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .highlight-box p {
            color: #ddd6fe;
            margin: 0;
        }

        .highlight-box strong {
            color: #a78bfa;
        }

        .output-section {
            background: rgba(15, 23, 42, 0.8);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid rgba(100, 116, 139, 0.3);
        }

        .output-section h3 {
            color: #e2e8f0;
            font-size: 1.1rem;
            margin-bottom: 1rem;
            font-weight: 600;
        }

        .filename {
            background: #1e293b;
            color: #fbbf24;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }

        .location-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(15, 23, 42, 0.6);
            border-radius: 8px;
            overflow: hidden;
            margin: 1rem 0;
        }

        .location-table th,
        .location-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid rgba(100, 116, 139, 0.2);
        }

        .location-table th {
            background: rgba(30, 41, 59, 0.8);
            color: #f1f5f9;
            font-weight: 600;
        }

        .location-table td {
            color: #cbd5e1;
        }

        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            color: #64748b;
            font-size: 0.9rem;
            border-top: 1px solid rgba(100, 116, 139, 0.2);
        }

        ul {
            list-style: none;
            padding-left: 0;
        }

        ul li {
            position: relative;
            padding-left: 1.5rem;
            margin-bottom: 0.5rem;
            color: #cbd5e1;
        }

        ul li:before {
            content: '•';
            color: #60a5fa;
            font-weight: bold;
            position: absolute;
            left: 0;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            h1 {
                font-size: 2rem;
            }
            
            .section {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Script Execution Guide</h1>
            <p class="subtitle">Complete instructions and requirements for executing security scripts across different platforms and components</p>
        </div>

        <div class="toc">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#windows-platforms">Windows Platforms</a></li>
                <li><a href="#linux-distributions">Linux Distributions</a></li>
                <li><a href="#database-systems">Database Systems</a></li>
                <li><a href="#output-structure">Output Structure</a></li>
                <li><a href="#best-practices">Best Practices</a></li>
            </ul>
        </div>

        <div class="section" id="windows-platforms">
            <h2>Windows Platforms</h2>
            
            <div class="subsection">
                <h3>Windows Server 2008–2012</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">WindowsServer2008-2012.ps1</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>PowerShell 5.1, Administrator privileges</td>
                    </tr>
                </table>
                <pre class="powershell"><span class="code-label">PowerShell</span><code>Set-ExecutionPolicy RemoteSigned -Scope Process
& "C:\Path\To\WindowsServer2008-2012.ps1"</code></pre>
            </div>

            <div class="subsection">
                <h3>Windows Server 2012 and Above</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">WindowsServer2012+.ps1</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>PowerShell 5.1 or newer, Administrator privileges</td>
                    </tr>
                </table>
                <pre class="powershell"><span class="code-label">PowerShell</span><code>Set-ExecutionPolicy RemoteSigned -Scope Process
& "C:\Path\To\WindowsServer2012+.ps1"</code></pre>
            </div>
        </div>

        <div class="section" id="linux-distributions">
            <h2>Linux Distributions</h2>
            
            <div class="subsection">
                <h3>Red Hat Enterprise Linux 6–7</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">RedHatEnterpriseLinux6-7.sh</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>Root/sudo access</td>
                    </tr>
                </table>
                <pre class="bash"><span class="code-label">Bash</span><code>chmod +x RedHatEnterpriseLinux6-7.sh
sudo ./RedHatEnterpriseLinux6-7.sh</code></pre>
            </div>

            <div class="subsection">
                <h3>Red Hat Enterprise Linux 8–9</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">RedHatEnterpriseLinux8-9.sh</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>Root/sudo access</td>
                    </tr>
                </table>
                <pre class="bash"><span class="code-label">Bash</span><code>chmod +x RedHatEnterpriseLinux8-9.sh
sudo ./RedHatEnterpriseLinux8-9.sh</code></pre>
            </div>

            <div class="subsection">
                <h3>Ubuntu 16.04–18.04</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">Ubuntu16-18.04.sh</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>Root/sudo access</td>
                    </tr>
                </table>
                <pre class="bash"><span class="code-label">Bash</span><code>chmod +x Ubuntu16-18.04.sh
sudo ./Ubuntu16-18.04.sh</code></pre>
            </div>

            <div class="subsection">
                <h3>Ubuntu 20.04–24.04</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">Ubuntu20.24.04.sh</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>Root/sudo access</td>
                    </tr>
                </table>
                <pre class="bash"><span class="code-label">Bash</span><code>chmod +x Ubuntu20.24.04.sh
sudo ./Ubuntu20.24.04.sh</code></pre>
            </div>
        </div>

        <div class="section" id="database-systems">
            <h2>Database Systems</h2>
            
            <div class="subsection">
                <h3>PostgreSQL 11 / 13 / 15</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">PostgreSQL111315.sh</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td><code>psql</code> command available, access configured (e.g., <code>.pgpass</code>)</td>
                    </tr>
                </table>
                <pre class="bash"><span class="code-label">Bash</span><code>chmod +x PostgreSQL111315.sh
./PostgreSQL111315.sh</code></pre>
            </div>

            <div class="subsection">
                <h3>SQL Server 2016–2019</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">MSSQLServer201619.ps1</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td>PowerShell + SQLPS module, DBA permissions</td>
                    </tr>
                </table>
                <pre class="powershell"><span class="code-label">PowerShell</span><code>Set-ExecutionPolicy RemoteSigned -Scope Process
& "C:\Path\To\MSSQLServer201619.ps1"</code></pre>
            </div>

            <div class="subsection">
                <h3>MongoDB 4.x / 6.x</h3>
                <table class="info-table">
                    <tr>
                        <th>Component</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><strong>Script</strong></td>
                        <td><span class="filename">MongoDB4x6x.sh</span></td>
                    </tr>
                    <tr>
                        <td><strong>Requirements</strong></td>
                        <td><code>mongo</code> CLI installed and in <code>$PATH</code></td>
                    </tr>
                </table>
                <pre class="bash"><span class="code-label">Bash</span><code>chmod +x MongoDB4x6x.sh
./MongoDB4x6x.sh</code></pre>
            </div>
        </div>

        <div class="section" id="output-structure">
            <h2>Output Structure</h2>
            
            <div class="output-section">
                <h3>Folder Naming Convention</h3>
                <p>Each script generates an output folder with the following naming pattern:</p>
                <pre><code>&lt;hostname&gt;_&lt;version&gt;_&lt;date&gt;</code></pre>
                <p><strong>Example:</strong></p>
                <pre><code>srv-app01_Ubuntu20_24_2025-07-31_14-12-00</code></pre>
            </div>

            <div class="output-section">
                <h3>Output Locations</h3>
                <table class="location-table">
                    <tr>
                        <th>Platform</th>
                        <th>Default Location</th>
                    </tr>
                    <tr>
                        <td><strong>Linux</strong></td>
                        <td><code>/tmp/</code></td>
                    </tr>
                    <tr>
                        <td><strong>Windows</strong></td>
                        <td>Current working directory</td>
                    </tr>
                </table>
            </div>

            <div class="output-section">
                <h3>Output Files</h3>
                <p>Each output folder contains:</p>
                <ul>
                    <li><strong>CSV files</strong> - Structured audit data</li>
                    <li><strong>TXT files</strong> - Detailed audit results and logs</li>
                </ul>
            </div>
        </div>

        <div class="section" id="best-practices">
            <h2>Best Practices</h2>
            
            <div class="highlight-box">
                <p><strong>Important:</strong> Always run scripts with appropriate elevated privileges</p>
            </div>

            <div class="output-section">
                <h3>Privilege Requirements</h3>
                <ul>
                    <li><strong>Linux:</strong> Use <code>sudo</code> for system-level audits</li>
                    <li><strong>Windows:</strong> Launch PowerShell as Administrator</li>
                </ul>
            </div>

            <div class="output-section">
                <h3>Environment Setup</h3>
                
                <h4 style="color: #94a3b8; margin: 1.5rem 0 1rem 0;">Linux Systems</h4>
                <pre class="bash"><span class="code-label">Bash</span><code># Set language environment if needed
export LANG=en_US.UTF-8</code></pre>

                <h4 style="color: #94a3b8; margin: 1.5rem 0 1rem 0;">Windows Systems</h4>
                <pre class="powershell"><span class="code-label">PowerShell</span><code># Launch PowerShell as Administrator from Start Menu
# Right-click PowerShell → "Run as Administrator"</code></pre>
            </div>
        </div>

        <div class="footer">
            <p>Last updated: July 31, 2025</p>
        </div>
    </div>
</body>
</html>
