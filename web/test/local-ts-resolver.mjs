import { extname } from 'node:path'

const src = new URL('../src/', import.meta.url).href

// Match Vite's extensionless relative imports in the application source.
export function resolve(specifier, context, next) {
  if (context.parentURL?.startsWith(src) && specifier.startsWith('./') && !extname(specifier)) {
    return next(`${specifier}.ts`, context)
  }
  return next(specifier, context)
}
