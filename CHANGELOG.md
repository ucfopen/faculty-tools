# Change Log

## [Unreleased]

### General

## [2.0.1] - 2020-05-21

### General

- Frame now scrolls to top when launching a tool
- Several GitHub-specific changes:
  - Added CODEOWNERS file
  - Added issue and PR templates
  - Removed GitLab CI file
  - Added Travis CI file

### Bugfixes

- Updated Session cookie to use `SameSite=None; Secure`
- Fixed a malformed format string

## [2.0.0] - 2019-12-16

### General

- Switched to Python 3
- Tools are now listed in the order they appear in whitelist.json

## [1.2.0] - 2019-09-10

### General

- Open Source release

## [1.1.0] - 2018-10-25

### General

- LTI window now expands to full size and resizes as needed.

### Bugfixes

- Fixed an issue where switching browsers would cause Faculty Tools to ask the
    user to reauthorize with Canvas, leading to multiple access tokens.

## [1.0.0] - 2018-08-29

### General

- Initial Release

[Unreleased]: https://github.com/ucfopen/faculty-tools/compare/v2.0.1...master
[2.0.1]: https://github.com/ucfopen/faculty-tools/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/ucfopen/faculty-tools/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/ucfopen/faculty-tools/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ucfopen/faculty-tools/compare/v1.0.0...v1.1.0
