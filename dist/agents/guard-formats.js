/**
 * Hook protocol adapters for tresor-guard. Every agent sends a different JSON
 * shape and expects a different "deny" answer; internally everything is mapped to
 * the Claude Code shape that `decide()` understands.
 *
 *   claude   Claude Code, OpenAI Codex, VS Code (local harness)  hookSpecificOutput.permissionDecision
 *   cursor   Cursor (beforeShellExecution / beforeReadFile / preToolUse)  {"permission": "deny"}
 *   gemini   Gemini CLI BeforeTool                                {"decision": "deny"}
 *   copilot  GitHub Copilot hooks (toolName / toolArgs)           {"permissionDecision": "deny"}
 *
 * Tool names differ per agent and some are undocumented, so classification is by
 * a broad name table plus whatever command/path fields are present.
 */
export const GUARD_FORMATS = ['claude', 'cursor', 'gemini', 'copilot'];
const SHELL_TOOLS = /^(bash|powershell|shell|exec_command|local_shell|run_shell_command|run_in_terminal|terminal|runinterminal)$/i;
const EDIT_TOOLS = /^(edit|multiedit|write|write_file|replace|create|createfile|editfiles|insert_edit_into_file|notebookedit|delete|apply_patch)$/i;
const asObject = (v) => {
    if (typeof v === 'string') {
        try {
            return JSON.parse(v);
        }
        catch {
            return {};
        }
    }
    return v && typeof v === 'object' ? v : {};
};
function commandOf(input) {
    const c = input.command ?? input.cmd ?? input.commandLine;
    return Array.isArray(c) ? c.join(' ') : typeof c === 'string' ? c : '';
}
function pathsOf(input) {
    const out = [];
    for (const k of ['file_path', 'filePath', 'path', 'absolute_path', 'file', 'target_file', 'notebook_path', 'dir_path']) {
        if (typeof input[k] === 'string')
            out.push(input[k]);
    }
    for (const k of ['paths', 'filePaths', 'files']) {
        if (Array.isArray(input[k]))
            out.push(...input[k].filter((p) => typeof p === 'string'));
    }
    return out;
}
/** Codex apply_patch carries file paths inside the patch text. */
function patchPaths(patch) {
    return [...patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)].map(m => m[1].trim());
}
/** Maps one tool call (any agent's naming) to Claude-shaped inputs for decide(). */
function generic(toolName, toolInput, cwd) {
    if (/^apply_patch$/i.test(toolName)) {
        return patchPaths(commandOf(toolInput) || String(toolInput.patch ?? toolInput.input ?? '')).map(p => ({ tool_name: 'Edit', tool_input: { file_path: p }, cwd }));
    }
    const command = commandOf(toolInput);
    if (SHELL_TOOLS.test(toolName) || (command && !pathsOf(toolInput).length)) {
        return command ? [{ tool_name: 'Bash', tool_input: { command }, cwd }] : [];
    }
    const kind = EDIT_TOOLS.test(toolName) ? 'Edit' : 'Read';
    return pathsOf(toolInput).map(p => ({ tool_name: kind, tool_input: { file_path: p }, cwd }));
}
export function normalize(format, raw) {
    const cwd = typeof raw.cwd === 'string' ? raw.cwd : Array.isArray(raw.workspace_roots) ? String(raw.workspace_roots[0] ?? '') : undefined;
    switch (format) {
        case 'cursor': {
            const event = String(raw.hook_event_name ?? '');
            if (event === 'beforeShellExecution')
                return [{ tool_name: 'Bash', tool_input: { command: String(raw.command ?? '') }, cwd }];
            if (event === 'beforeReadFile')
                return [{ tool_name: 'Read', tool_input: { file_path: String(raw.file_path ?? '') }, cwd }];
            if (event === 'beforeMCPExecution')
                return [];
            return generic(String(raw.tool_name ?? ''), asObject(raw.tool_input), cwd);
        }
        case 'copilot':
            if (raw.toolName !== undefined)
                return generic(String(raw.toolName), asObject(raw.toolArgs), cwd);
            return generic(String(raw.tool_name ?? ''), asObject(raw.tool_input), cwd);
        case 'gemini':
        case 'claude':
        default: {
            const name = String(raw.tool_name ?? '');
            // Claude's own names go through unchanged so existing rules keep their exact behaviour.
            if (format === 'claude' && /^(Bash|PowerShell|Read|Grep|Edit|MultiEdit|Write|NotebookEdit)$/.test(name)) {
                return [{ tool_name: name, tool_input: asObject(raw.tool_input), cwd }];
            }
            return generic(name, asObject(raw.tool_input), cwd);
        }
    }
}
export function render(format, reason) {
    switch (format) {
        case 'cursor':
            // Cursor blocks on invalid JSON, so "allow" must be explicit.
            return reason
                ? { stdout: JSON.stringify({ continue: true, permission: 'deny', user_message: reason, agent_message: reason }), exitCode: 0 }
                : { stdout: JSON.stringify({ continue: true, permission: 'allow' }), exitCode: 0 };
        case 'gemini':
            return { stdout: reason ? JSON.stringify({ decision: 'deny', reason }) : '', exitCode: 0 };
        case 'copilot':
            return { stdout: reason ? JSON.stringify({ permissionDecision: 'deny', permissionDecisionReason: reason }) : '', exitCode: 0 };
        case 'claude':
        default:
            return {
                stdout: reason ? JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }) : '',
                exitCode: 0,
            };
    }
}
