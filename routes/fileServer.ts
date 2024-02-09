/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import sanitizeFilename from 'sanitize-filename';

import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges

module.exports = function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify(file: string, res: Response, next: NextFunction) {
    // Decode the file name to handle percent encoding
    file = decodeURIComponent(file);

    // Sanitize the file name to remove any potentially dangerous characters
    const sanitizedFileName = file.replace(/%.*/, '');

    // Check if the sanitized file name contains null bytes
    if (sanitizedFileName && sanitizedFileName.includes('\0')) {
        res.status(403);
        return next(new Error('File names cannot contain null bytes!'));
    }

    // Check if the sanitized file name contains forward slashes
    if (sanitizedFileName && sanitizedFileName.includes('/')) {
        res.status(403);
        return next(new Error('File names cannot contain forward slashes!'));
    }

    // Check if the file is allowed based on its extension and presence in the forbidden files list
    if (sanitizedFileName && endsWithAllowlistedFileType(sanitizedFileName) && verifySuccessfulPoisonNullByteExploit(sanitizedFileName)) {
        // Perform other verifications and processing
        const filePath = path.resolve('ftp/', sanitizedFileName);
        res.sendFile(filePath);
    } else {
        res.status(403);
        next(new Error('Only .md and .pdf files are allowed!'));
    }
}


  function verifySuccessfulPoisonNullByteExploit (file: string) {
    const forbiddenFiles = ['eastere.gg', 'package.json.bak', 'coupons_2013.md.bak', 'suspicious_errors.yml', 'encrypt.pyc'];

    return !forbiddenFiles.includes(file.toLowerCase());
  }

  function endsWithAllowlistedFileType(param: string) {
    const allowedExtensions = ['.md', '.pdf'];
  
    // Sanitize the file name
    const sanitizedFileName = sanitizeFilename(param);
  
    // Check if the sanitized file name ends with one of the allowed extensions
    return allowedExtensions.some(extension => sanitizedFileName.toLowerCase().endsWith(extension));
  }
}
