import { type RepoPayload } from './repo';
export declare const REPO_MERGE_TYPE = "repo.merge";
/** Most files (added, changed and removed together) one approval may cover. Above this: split the change. */
export declare const MAX_REPO_FILES = 100;
/** Most characters the file list may take on screen. Guards against a few very long paths. */
export declare const MAX_REPO_LIST_CHARS = 20000;
/** True only for a payload of exactly the repo shape, with no extra fields (an extra field would be signed but
 *  not shown, so it is refused). */
export declare function isRepoPayload(p: unknown): p is RepoPayload;
/** A path as the human sees it: quoted, with control, invisible and direction-changing characters written as
 *  \u{XXXX}, so nothing in a file name can hide, reorder or fake text on screen. */
export declare function showPath(p: string): string;
/** The file list shown for a repo merge. Throws (before any prompt) if the change is too big to read. */
export declare function renderRepoFiles(p: RepoPayload): string;
//# sourceMappingURL=repoDisplay.d.ts.map