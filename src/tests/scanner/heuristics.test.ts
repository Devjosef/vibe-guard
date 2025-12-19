import { FileScanner } from '../../scanner';

describe('FileScanner.isSupportedFile', () => {
  let scanner: FileScanner;

  beforeEach(() => {
    scanner = new FileScanner();
  });

  it('excludes binary extensions → false', () => {
    expect(scanner['isSupportedFile']('/file.exe')).toBe(false);
    expect(scanner['isSupportedFile']('/image.png')).toBe(false);
    expect(scanner['isSupportedFile']('/data.db')).toBe(false);
  });

  it('includes source files → true', () => {
    expect(scanner['isSupportedFile']('/app.js')).toBe(true);
    expect(scanner['isSupportedFile']('/main.ts')).toBe(true);
    expect(scanner['isSupportedFile']('/config.json')).toBe(true);
  });

  it('unknown extension → false', () => {
    expect(scanner['isSupportedFile']('/script.random')).toBe(false);
  });

  it('case insensitive extensions', () => {
    expect(scanner['isSupportedFile']('/App.JS')).toBe(true);
    expect(scanner['isSupportedFile']('/IMAGE.PNG')).toBe(false);
  });

  it('no extension → false', () => {
    expect(scanner['isSupportedFile']('/file')).toBe(false);
  });

  it('dotfiles with supported extensions → false', () => {
    expect(scanner['isSupportedFile']('/.env')).toBe(false);
    expect(scanner['isSupportedFile']('/.js')).toBe(false);
  });

  it('directory paths → false', () => {
    expect(scanner['isSupportedFile']('/dir/')).toBe(false);
    expect(scanner['isSupportedFile']('/dir/file.js')).toBe(true);
  });
});
