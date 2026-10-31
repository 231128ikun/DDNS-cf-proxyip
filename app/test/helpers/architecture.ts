import ts from 'typescript';
import { posix } from 'node:path';

/** 检查实际语法节点，避免把注释里的示例或多行 import 漏判为依赖。 */
export function architectureViolations(file: string, text: string): string[] {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const failures: string[] = [];
  const core = /^src\/(domain|contracts|ports|application)\//.test(file);
  const pureUtil = /^src\/util\/(concurrency|key-order|time)\.ts$/.test(file);
  const browser = file.startsWith('web/src/');
  const ioForbidden = core || pureUtil || (browser && file !== 'web/src/api/client.ts');
  const dependency = (specifier: string): void => {
    const target = specifier.startsWith('.') ? posix.normalize(posix.join(posix.dirname(file), specifier)) : specifier;
    if (core || pureUtil || /^src\/(jobs|transport|adapters)\//.test(file)) {
      const layer = file.split('/')[1];
      const allowed = layer === 'application' ? /^src\/(application|domain|contracts|ports)\//
        : layer === 'jobs' || layer === 'transport' ? /^src\/(jobs|transport|application|domain|contracts|ports)\//
        : layer === 'adapters' ? /^src\/(adapters|domain|contracts|ports|util)\//
        : layer === 'ports' ? /^src\/(domain|contracts|ports)\// : /^src\/(domain|contracts)\//;
      if (!allowed.test(target) && !/^src\/util\/(concurrency|key-order|time)$/.test(target)) failures.push(`forbidden dependency ${target}`);
    }
    if (browser && target.startsWith('src/') && !/^src\/(contracts|domain|ports)\//.test(target)
      && !/^src\/util\/(concurrency|key-order|time)$/.test(target)) failures.push(`browser backend dependency ${target}`);
  };
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) dependency(node.moduleSpecifier.text);
    if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteral(node.argument.literal)) dependency(node.argument.literal.text);
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require')) {
        const argument = node.arguments[0];
        if (argument && ts.isStringLiteral(argument)) dependency(argument.text);
        else if (core || pureUtil || browser) failures.push('non-literal module dependency');
      }
      const name = ts.isIdentifier(node.expression) ? node.expression.text
        : ts.isPropertyAccessExpression(node.expression) ? node.expression.name.text
        : ts.isElementAccessExpression(node.expression) && node.expression.argumentExpression && ts.isStringLiteral(node.expression.argumentExpression) ? node.expression.argumentExpression.text : '';
      if (ioForbidden && name === 'fetch') failures.push('direct fetch outside IO boundary');
    }
    if ((core || pureUtil) && ts.isTypeReferenceNode(node) && ['KVNamespace', 'Request', 'Response', 'RuntimeEnv'].includes(node.typeName.getText(source))) failures.push('infrastructure type in core');
    ts.forEachChild(node, visit);
  };
  visit(source);
  return failures;
}
